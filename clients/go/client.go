// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package tsm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// ProtocolVersion is the protocol version this library speaks.
	ProtocolVersion = 1
	// MaxGetMany is the most references one GetMany carries.
	MaxGetMany = 256
	// ClientVersion is this library's version, sent in hello.
	ClientVersion = "0.1.0"
)

// ClientFeatures are the optional features (section 8) this library takes:
// binary frames and getFile.
var ClientFeatures = []string{"binary", "getFile"}

// Welcome is what the service said in welcome: the protocol, its version,
// the optional features it offers (sorted), its host name (the current
// value of the host dimension) and platform.
type Welcome struct {
	Protocol       int
	ServiceVersion string
	Features       []string
	Host           string
	Platform       string
}

// Offers says whether the service offers feature.
func (w *Welcome) Offers(feature string) bool {
	for _, f := range w.Features {
		if f == feature {
			return true
		}
	}
	return false
}

type clientOptions struct {
	name            string
	token           string
	environment     map[string]string
	operatingSystem string
	connectTimeout  time.Duration
}

// Option configures a [Client].
type Option func(*clientOptions)

// WithClientName is the name hello gives the program, shown in approval
// prompts and never trusted (the service measures the process). Default:
// the executable's name.
func WithClientName(name string) Option { return func(o *clientOptions) { o.name = name } }

// WithClientToken is a client token the program was granted before (7.4),
// sent with every connection.
func WithClientToken(token string) Option { return func(o *clientOptions) { o.token = token } }

// WithEnvironment is where TSM_RUNTIME_DIR and the OS variables are read
// from. Default: the process's environment.
func WithEnvironment(environment map[string]string) Option {
	return func(o *clientOptions) { o.environment = environment }
}

// WithOperatingSystem is "linux", "macos" or "windows". Default: this
// process's.
func WithOperatingSystem(name string) Option {
	return func(o *clientOptions) { o.operatingSystem = name }
}

// WithConnectTimeout bounds connecting and the service's welcome. Default
// 10 seconds.
func WithConnectTimeout(d time.Duration) Option {
	return func(o *clientOptions) { o.connectTimeout = d }
}

type requestOptions struct {
	field           string
	dimensions      map[string]string
	noWait          bool
	timeoutMs       int64
	hasTimeout      bool
	onProgress      func(Progress)
	wantClientToken bool
	waitOnRateLimit bool
}

// RequestOption configures one Get, GetMany or GetFile.
type RequestOption func(*requestOptions)

// WithField names the field when the reference names none (Get and
// GetFile; a GetMany names it per [Request]). The same field in both is
// sent once; two different ones are malformed, reason field_twice.
func WithField(field string) RequestOption { return func(o *requestOptions) { o.field = field } }

// WithDimensions are values for dimensions beside the reference
// ({"env": "prod"}; Get and GetFile).
func WithDimensions(dimensions map[string]string) RequestOption {
	return func(o *requestOptions) { o.dimensions = dimensions }
}

// NoWait answers at once instead of waiting for an unlock or an approval
// (locked when the service is locked).
func NoWait() RequestOption { return func(o *requestOptions) { o.noWait = true } }

// WithTimeout is how long the service may wait for an unlock or an
// approval, in whole milliseconds, capped by the service.
func WithTimeout(d time.Duration) RequestOption {
	return func(o *requestOptions) { o.timeoutMs, o.hasTimeout = d.Milliseconds(), true }
}

// WithProgress receives the progress notices while the request waits. It
// is called on the connection's reader goroutine: it must return quickly.
func WithProgress(f func(Progress)) RequestOption {
	return func(o *requestOptions) { o.onProgress = f }
}

// WithClientTokenRequest asks for a client token with an "always" approval
// (Get only).
func WithClientTokenRequest() RequestOption {
	return func(o *requestOptions) { o.wantClientToken = true }
}

// WaitOnRateLimit waits out a rate_limited answer (its retryAfterMs, else
// one second) and sends the request again. denied, ambiguous and not_found
// are never retried.
func WaitOnRateLimit() RequestOption { return func(o *requestOptions) { o.waitOnRateLimit = true } }

// Client is a client of the Tom Secrets Manager's secrets service: one
// connection, opened by the first call (or Open); after not_running or a
// dropped connection the next call connects again. It is safe for
// concurrent use, and calls overlap on the one connection. The library
// logs nothing: no value, token or payload.
type Client struct {
	opts      clientOptions
	mu        sync.Mutex
	connectMu sync.Mutex
	conn      *connection
}

// New is a client that connects on its first call.
func New(options ...Option) *Client {
	o := clientOptions{connectTimeout: 10 * time.Second}
	for _, option := range options {
		option(&o)
	}
	if o.name == "" {
		o.name = executableName()
	}
	if o.environment == nil {
		o.environment = processEnvironment()
	}
	if o.operatingSystem == "" {
		o.operatingSystem = CurrentOperatingSystem()
	}
	return &Client{opts: o}
}

// Connect is a client connected at once, so a missing service shows as
// not_running right away.
func Connect(ctx context.Context, options ...Option) (*Client, error) {
	c := New(options...)
	if err := c.Open(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func executableName() string {
	if len(os.Args) == 0 || os.Args[0] == "" {
		return "go"
	}
	name := filepath.Base(os.Args[0])
	if strings.HasSuffix(strings.ToLower(name), ".exe") {
		name = name[:len(name)-4]
	}
	return name
}

// ClientName is the name hello gives the program.
func (c *Client) ClientName() string { return c.opts.name }

// Welcome is the service's welcome on the current connection, or nil.
func (c *Client) Welcome() *Welcome {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil || conn.isClosed() {
		return nil
	}
	return conn.welcomeOf()
}

// Open connects, unless a connection is open.
func (c *Client) Open(ctx context.Context) error {
	_, err := c.ensure(ctx)
	return err
}

// Close closes the connection; a later call connects again. It always
// returns nil.
func (c *Client) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		conn.fail(notRunning("the client closed the connection"))
	}
	return nil
}

// Get reads one secret. The reference is parsed locally first: a malformed
// one fails as [KindMalformed] without a round trip, and so does a request
// over 64 KiB (reason frame).
func (c *Client) Get(ctx context.Context, ref string, options ...RequestOption) (*Value, error) {
	o := requestOptionsOf(options)
	item, err := requestItem(ref, o.field, o.dimensions)
	if err != nil {
		return nil, err
	}
	request := message{"op": "get"}
	for k, v := range item {
		request[k] = v
	}
	o.addWaiting(request)
	if o.wantClientToken {
		request["wantClientToken"] = true
	}
	a, err := c.request(ctx, request, o)
	if err != nil {
		return nil, err
	}
	return valueOf(ref, a.m)
}

// GetMany reads 1 to [MaxGetMany] secrets under one approval prompt; the
// results come in request order, each a Value or an error. Every reference
// is parsed locally first. WithField, WithDimensions and
// WithClientTokenRequest do not apply (a [Request] carries its field and
// dimensions): they, and a count out of range, are a plain error.
func (c *Client) GetMany(ctx context.Context, requests []Request, options ...RequestOption) ([]Result, error) {
	o := requestOptionsOf(options)
	if len(requests) == 0 || len(requests) > MaxGetMany {
		return nil, fmt.Errorf("tsm: a GetMany carries 1 to %d references, not %d", MaxGetMany, len(requests))
	}
	if o.field != "" || o.dimensions != nil || o.wantClientToken {
		return nil, errors.New("tsm: WithField, WithDimensions and WithClientTokenRequest do not apply to GetMany")
	}
	items := make([]any, len(requests))
	for i, r := range requests {
		item, err := requestItem(r.Ref, r.Field, r.Dimensions)
		if err != nil {
			return nil, err
		}
		items[i] = item
	}
	request := message{"op": "getMany", "refs": items}
	o.addWaiting(request)
	a, err := c.request(ctx, request, o)
	if err != nil {
		return nil, err
	}
	results, ok := a.m["results"].([]any)
	if a.m["op"] != "values" || !ok {
		return nil, protocolError(fmt.Sprintf("getMany was answered %v", a.m["op"]))
	}
	if len(results) != len(requests) {
		return nil, protocolError(fmt.Sprintf("getMany got %d results", len(results)))
	}
	out := make([]Result, len(results))
	for i, r := range results {
		result, ok := r.(map[string]any)
		if !ok {
			return nil, protocolError("a getMany result is no object")
		}
		if result["op"] == "error" {
			out[i] = Result{Err: errorFromMessage(result)}
			continue
		}
		v, err := valueFromMessage(requests[i].Ref, result)
		if err != nil {
			return nil, err
		}
		out[i] = Result{Value: v}
	}
	return out, nil
}

// GetFile reads an attachment or a typed key as bytes (5.5), over binary
// frames, checked against its size and SHA-256. It fails as
// [KindUnsupported] when the service does not offer the features binary
// and getFile (details.features names the missing ones).
func (c *Client) GetFile(ctx context.Context, ref string, options ...RequestOption) (*File, error) {
	o := requestOptionsOf(options)
	if o.wantClientToken {
		return nil, errors.New("tsm: WithClientTokenRequest applies to Get only")
	}
	item, err := requestItem(ref, o.field, o.dimensions)
	if err != nil {
		return nil, err
	}
	conn, err := c.ensure(ctx)
	if err != nil {
		return nil, err
	}
	var missing []any
	for _, f := range ClientFeatures {
		if !conn.welcomeOf().Offers(f) {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		names := make([]string, len(missing))
		for i, m := range missing {
			names[i] = m.(string)
		}
		return nil, &Error{KindUnsupported,
			"the service does not offer getFile (features " + strings.Join(names, ", ") + ")",
			map[string]any{"features": missing}}
	}
	request := message{"op": "getFile"}
	for k, v := range item {
		request[k] = v
	}
	o.addWaiting(request)
	a, err := c.request(ctx, request, o)
	if err != nil {
		return nil, err
	}
	if a.m["op"] != "end" || a.file == nil {
		return nil, protocolError(fmt.Sprintf("getFile was answered %v", a.m["op"]))
	}
	name, nameOK := a.file["name"].(string)
	size, sizeOK := intOf(a.file["size"])
	sum := sha256.Sum256(a.data)
	if !nameOK || !sizeOK || size != int64(len(a.data)) || a.m["sha256"] != hex.EncodeToString(sum[:]) {
		clear(a.data)
		return nil, protocolError("the file does not match its size or sha256")
	}
	return &File{Reference: ref, Name: name, data: a.data}, nil
}

func requestOptionsOf(options []RequestOption) *requestOptions {
	o := &requestOptions{}
	for _, option := range options {
		option(o)
	}
	return o
}

func (o *requestOptions) addWaiting(request message) {
	if o.noWait {
		request["wait"] = false
	}
	if o.hasTimeout {
		request["timeoutMs"] = o.timeoutMs
	}
}

func requestItem(ref, field string, dimensions map[string]string) (message, error) {
	parsed, err := ParseReference(ref)
	if err != nil {
		return nil, err
	}
	if field != "" && parsed.FieldGiven && field != parsed.Field {
		return nil, malformed("field_twice", "the field is named in the reference and as field")
	}
	item := message{"ref": ref}
	if len(dimensions) > 0 {
		d := make(map[string]any, len(dimensions))
		for k, v := range dimensions {
			d[k] = v
		}
		item["dimensions"] = d
	}
	if field != "" && !parsed.FieldGiven {
		item["field"] = field
	}
	return item, nil
}

func valueOf(ref string, m message) (*Value, error) {
	if m["op"] != "value" {
		return nil, protocolError(fmt.Sprintf("get was answered %v", m["op"]))
	}
	return valueFromMessage(ref, m)
}

func (c *Client) request(ctx context.Context, request message, o *requestOptions) (answer, error) {
	for {
		conn, err := c.ensure(ctx)
		if err != nil {
			return answer{}, err
		}
		a, err := conn.send(ctx, request, o.onProgress)
		if err != nil {
			return answer{}, err
		}
		if a.m["op"] != "error" {
			return a, nil
		}
		e := errorFromMessage(a.m)
		if e.Kind != KindRateLimited || !o.waitOnRateLimit {
			return answer{}, e
		}
		wait := time.Second
		if ms, ok := intOf(e.Details["retryAfterMs"]); ok && ms > 0 {
			wait = time.Duration(ms) * time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return answer{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *Client) ensure(ctx context.Context) (*connection, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil && !conn.isClosed() {
		return conn, nil
	}
	c.connectMu.Lock()
	defer c.connectMu.Unlock()
	c.mu.Lock()
	conn = c.conn
	c.mu.Unlock()
	if conn != nil && !conn.isClosed() {
		return conn, nil
	}
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	return conn, nil
}

func readText(path string) (string, bool) {
	data, err := os.ReadFile(path)
	return string(data), err == nil
}

func (c *Client) connect(ctx context.Context) (*connection, error) {
	o := c.opts
	location, ok := Discover(o.operatingSystem, o.environment, os.Getuid)
	if !ok {
		return nil, notRunning("no runtime directory can be named")
	}
	dialCtx, cancel := context.WithTimeout(ctx, o.connectTimeout)
	defer cancel()
	var dialer net.Dialer
	var netConn net.Conn
	var err error
	token := ""
	if o.operatingSystem == "windows" {
		text, read := readText(location.ClientPortFile)
		port, valid := ReadPortFile(text)
		if !read || !valid {
			return nil, notRunning("no readable client.port")
		}
		raw, read := readText(location.ClientTokenFile)
		if !read {
			return nil, notRunning("no client.token")
		}
		token = stripLineEnd(raw)
		netConn, err = dialer.DialContext(dialCtx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	} else {
		if _, statErr := os.Stat(location.ClientSocket); statErr != nil {
			return nil, notRunning("no client.sock in " + location.Directory)
		}
		netConn, err = dialer.DialContext(dialCtx, "unix", location.ClientSocket)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if dialCtx.Err() != nil {
			return nil, notRunning("the connection timed out")
		}
		return nil, notRunning("the connection was refused")
	}
	conn := newConnection(netConn)
	hello := message{
		"op":       "hello",
		"protocol": ProtocolVersion,
		"client": message{
			"name":     o.name,
			"version":  ClientVersion,
			"language": "go",
		},
		"features": append([]string(nil), ClientFeatures...),
	}
	if token != "" {
		hello["token"] = token
	}
	if o.token != "" {
		hello["clientToken"] = o.token
	}
	if err := conn.write(hello); err != nil {
		conn.fail(dropped())
		return nil, err
	}
	select {
	case <-conn.welcomed:
		if e := conn.failure(); e != nil {
			return nil, e
		}
		return conn, nil
	case <-dialCtx.Done():
		conn.fail(notRunning("no welcome"))
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, notRunning(fmt.Sprintf("no welcome within %d ms", o.connectTimeout.Milliseconds()))
	}
}

func dropped() *Error { return notRunning("the connection to the service dropped") }

// answer is a request's last message; for getFile also the file message
// and the bytes of its chunks.
type answer struct {
	m    message
	file message
	data []byte
	err  error
}

type pending struct {
	ch         chan answer
	onProgress func(Progress)
	abandoned  bool
	file       message
	chunks     []byte
}

// connection is one connection: frames in and out, the open requests by id.
type connection struct {
	netConn  net.Conn
	writeMu  sync.Mutex
	mu       sync.Mutex
	closed   bool
	err      *Error
	welcome  *Welcome
	welcomed chan struct{}
	// welcomeOnce closes welcomed once: at the welcome or at a failure
	// before it, whichever comes first.
	welcomeOnce sync.Once
	pending     map[int64]*pending
	nextID      int64
	frames      frameReader
}

func newConnection(netConn net.Conn) *connection {
	c := &connection{
		netConn:  netConn,
		welcomed: make(chan struct{}),
		pending:  map[int64]*pending{},
		nextID:   1,
		frames:   frameReader{maxPayload: MaxAnswerPayload},
	}
	go c.read()
	return c
}

func (c *connection) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *connection) welcomeOf() *Welcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.welcome
}

func (c *connection) failure() *Error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *connection) write(m message) error {
	payload, err := jsonPayload(m)
	if err != nil {
		return fmt.Errorf("tsm: the request cannot be written as JSON: %w", err)
	}
	if len(payload) > MaxRequestPayload {
		return malformed("frame", fmt.Sprintf("the request is %d bytes, over %d", len(payload), MaxRequestPayload))
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.netConn.Write(encodeFrame(frameJSON, payload)); err != nil {
		return dropped()
	}
	return nil
}

func (c *connection) send(ctx context.Context, request message, onProgress func(Progress)) (answer, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return answer{}, dropped()
	}
	id := c.nextID
	c.nextID++
	p := &pending{ch: make(chan answer, 1), onProgress: onProgress}
	c.pending[id] = p
	c.mu.Unlock()
	framed := message{"id": id}
	for k, v := range request {
		framed[k] = v
	}
	if err := c.write(framed); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		if KindOf(err) == KindNotRunning {
			c.fail(dropped())
		}
		return answer{}, err
	}
	select {
	case a := <-p.ch:
		return a, a.err
	case <-ctx.Done():
		// The answer still comes (chunks too) and is dropped when it does.
		c.mu.Lock()
		p.abandoned = true
		c.mu.Unlock()
		return answer{}, ctx.Err()
	}
}

func (c *connection) read() {
	buffer := make([]byte, 64*1024)
	for {
		n, err := c.netConn.Read(buffer)
		if n > 0 {
			frames, ferr := c.frames.add(buffer[:n])
			clear(buffer[:n])
			if ferr != nil {
				c.fail(protocolError(ferr.Error()))
				return
			}
			for _, f := range frames {
				var e *Error
				if f.frameType == frameBinary {
					e = c.onChunk(f.payload)
				} else {
					m, derr := decodePayload(f.payload)
					clear(f.payload)
					if derr != nil {
						e = protocolError(derr.Error())
					} else {
						e = c.onMessage(m)
					}
				}
				if e != nil {
					c.fail(e)
					return
				}
				if c.isClosed() {
					return
				}
			}
		}
		if err != nil {
			// EOF, or the socket closed under the reader: the connection
			// is gone (a no-op when fail closed it already).
			c.fail(dropped())
			return
		}
	}
}

func welcomeOf(m message) (*Welcome, *Error) {
	if protocol, ok := intOf(m["protocol"]); !ok || protocol != ProtocolVersion {
		return nil, &Error{KindUnsupported, fmt.Sprintf("the service speaks protocol %v", m["protocol"]),
			map[string]any{"protocols": []any{m["protocol"]}}}
	}
	w := &Welcome{Protocol: ProtocolVersion}
	if service, ok := m["service"].(map[string]any); ok {
		w.ServiceVersion = fmt.Sprint(service["version"])
	}
	if features, ok := m["features"].([]any); ok {
		for _, f := range features {
			if s, ok := f.(string); ok {
				w.Features = append(w.Features, s)
			}
		}
		sort.Strings(w.Features)
	}
	w.Host, _ = m["host"].(string)
	w.Platform, _ = m["platform"].(string)
	return w, nil
}

func (c *connection) onMessage(m message) *Error {
	op, _ := m["op"].(string)
	rawID, hasID := m["id"]
	if c.welcome == nil {
		switch {
		case op == "welcome":
			w, e := welcomeOf(m)
			if e != nil {
				return e
			}
			c.mu.Lock()
			c.welcome = w
			c.mu.Unlock()
			c.frames.binaryAllowed = w.Offers("binary")
			c.welcomeOnce.Do(func() { close(c.welcomed) })
			return nil
		case op == "error" && !hasID:
			return errorFromMessage(m)
		default:
			return protocolError("the first frame is " + op + ", not welcome")
		}
	}
	if op == "error" && !hasID {
		return errorFromMessage(m)
	}
	id, ok := intOf(rawID)
	if !ok {
		return nil // an answer nobody waits for; ignored
	}
	c.mu.Lock()
	p := c.pending[id]
	c.mu.Unlock()
	if p == nil {
		return nil
	}
	switch op {
	case "progress":
		c.mu.Lock()
		abandoned := p.abandoned
		c.mu.Unlock()
		if p.onProgress != nil && !abandoned {
			pending := "approval"
			if m["pending"] == "unlock" {
				pending = "unlock"
			}
			code, _ := m["approvalCode"].(string)
			p.onProgress(Progress{pending, code})
		}
	case "file":
		c.mu.Lock()
		p.file = m
		p.chunks = []byte{}
		c.mu.Unlock()
	case "end":
		c.mu.Lock()
		file, data := p.file, p.chunks
		c.mu.Unlock()
		if file == nil {
			return protocolError("end without file")
		}
		c.complete(id, answer{m: m, file: file, data: data})
	case "value", "values", "error":
		c.complete(id, answer{m: m})
	}
	// Any other answer is one this library does not know: section 8 says
	// ignore it.
	return nil
}

func (c *connection) onChunk(payload []byte) *Error {
	if len(payload) < 8 {
		return protocolError("a binary chunk without id")
	}
	id := int64(payload[0])<<56 | int64(payload[1])<<48 | int64(payload[2])<<40 | int64(payload[3])<<32 |
		int64(payload[4])<<24 | int64(payload[5])<<16 | int64(payload[6])<<8 | int64(payload[7])
	c.mu.Lock()
	defer c.mu.Unlock()
	defer clear(payload)
	p := c.pending[id]
	if p == nil || p.file == nil {
		return protocolError("a chunk without file")
	}
	p.chunks = append(p.chunks, payload[8:]...)
	return nil
}

func (c *connection) complete(id int64, a answer) {
	c.mu.Lock()
	p := c.pending[id]
	delete(c.pending, id)
	abandoned := p != nil && p.abandoned
	c.mu.Unlock()
	if p == nil {
		return
	}
	if abandoned {
		clear(a.data)
		return
	}
	p.ch <- a
}

func (c *connection) fail(e *Error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.err = e
	var waiting []*pending
	for _, p := range c.pending {
		clear(p.chunks)
		if !p.abandoned {
			waiting = append(waiting, p)
		}
	}
	c.pending = map[int64]*pending{}
	c.mu.Unlock()
	c.welcomeOnce.Do(func() { close(c.welcomed) })
	for _, p := range waiting {
		p.ch <- answer{err: e}
	}
	_ = c.netConn.Close()
}
