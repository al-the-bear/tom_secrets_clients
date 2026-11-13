// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Checks vectors/signatures.json, approval_codes.json and
// link_handshake.json (section 9 of protocol.md) with an implementation
// independent of the Dart and Python tools that write them: Go's standard
// library (crypto/ed25519, crypto/mldsa, crypto/mlkem, crypto/ecdh,
// crypto/hmac), and ChaCha20-Poly1305 written out from RFC 8439
// (chacha20poly1305.go; the standard library keeps its own internal). Every
// signed byte string, signature, code, token, handshake message, key and
// transport frame is recomputed from the seeds, keys and coins in the files
// and compared. The module requires nothing beyond the standard library.
//
//	cd protocol/tool/vectors_go && go run .
//
// Run by hand with Go 1.27 or later after the vectors change. Exit 0 when
// everything matches.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var failures []string

func check(ok bool, format string, args ...any) {
	if !ok {
		failures = append(failures, fmt.Sprintf(format, args...))
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func b64(s any) []byte   { return must(base64.StdEncoding.DecodeString(s.(string))) }
func unhex(s any) []byte { return must(hex.DecodeString(s.(string))) }

// lp is u32be(len) || bytes.
func lp(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

func lps(s string) []byte { return lp([]byte(s)) }

var signedFields = map[string][]string{
	"tsm-grant-v1":     {"id", "host", "subject", "secret", "decision", "created", "pin", "approver"},
	"tsm-revoke-v1":    {"host", "grantId", "revoked", "approver"},
	"tsm-approval-v1":  {"host", "code", "decision", "approver", "created"},
	"tsm-keychange-v1": {"device", "oldKeyId", "newKeyId", "newEd25519", "newMlDsa65", "time"},
}

func pinText(v any) string {
	switch p := v.(type) {
	case nil:
		return ""
	case string:
		return p
	case map[string]any:
		return "relaxed:" + p["relaxedUntil"].(string)
	}
	panic("pin")
}

func signedBytes(label string, object map[string]any) []byte {
	out := lps(label)
	for _, name := range signedFields[label] {
		if name == "pin" {
			out = append(out, lps(pinText(object[name]))...)
		} else if s, ok := object[name].(string); ok {
			out = append(out, lps(s)...)
		} else {
			out = append(out, lps("")...)
		}
	}
	return out
}

func keyID(ed, ml []byte) string {
	h := sha256.Sum256(append(append(lps("tsm-approver-key-v1"), lp(ed)...), lp(ml)...))
	return hex.EncodeToString(h[:16])
}

type recorded struct{ ed, ml []byte }

func verifiedBy(id string, key recorded, label string, msg []byte, sigs []any) bool {
	edOK, mlOK := false, false
	pk := must(mldsa.NewPublicKey(mldsa.MLDSA65(), key.ml))
	for _, item := range sigs {
		s := item.(map[string]any)
		if s["keyId"] != id {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s["sig"].(string))
		if err != nil {
			continue
		}
		switch s["alg"] {
		case "ed25519":
			edOK = edOK || ed25519.Verify(key.ed, msg, sig)
		case "ml-dsa-65":
			mlOK = mlOK || mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: label}) == nil
		}
	}
	return edOK && mlOK
}

func accepts(label string, object map[string]any, keys map[string]recorded, old recorded) bool {
	msg := signedBytes(label, object)
	sigs := object["signatures"].([]any)
	if label == "tsm-keychange-v1" {
		nk := recorded{b64(object["newEd25519"]), b64(object["newMlDsa65"])}
		if keyID(nk.ed, nk.ml) != object["newKeyId"] || keyID(old.ed, old.ml) != object["oldKeyId"] {
			return false
		}
		return verifiedBy(object["oldKeyId"].(string), old, label, msg, sigs) &&
			verifiedBy(object["newKeyId"].(string), nk, label, msg, sigs)
	}
	for id, k := range keys {
		if verifiedBy(id, k, label, msg, sigs) {
			return true
		}
	}
	return false
}

func load(dir, name string) map[string]any {
	var v map[string]any
	if err := json.Unmarshal(must(os.ReadFile(filepath.Join(dir, name))), &v); err != nil {
		panic(err)
	}
	return v
}

func checkSignatures(v map[string]any) int {
	type pair struct {
		ed ed25519.PrivateKey
		ml *mldsa.PrivateKey
	}
	keys := map[string]pair{}
	pub := map[string]recorded{}
	for name, raw := range v["keys"].(map[string]any) {
		k := raw.(map[string]any)
		ed := ed25519.NewKeyFromSeed(b64(k["ed25519Seed"]))
		ml := must(mldsa.NewPrivateKey(mldsa.MLDSA65(), b64(k["mlDsa65Seed"])))
		edPub := ed.Public().(ed25519.PublicKey)
		mlPub := ml.PublicKey().Bytes()
		check(bytes.Equal(edPub, b64(k["ed25519Public"])), "key %s: Ed25519 public", name)
		check(bytes.Equal(mlPub, b64(k["mlDsa65Public"])), "key %s: ML-DSA-65 public", name)
		check(keyID(edPub, mlPub) == k["keyId"], "key %s: keyId", name)
		keys[k["keyId"].(string)] = pair{ed, ml}
		pub[k["keyId"].(string)] = recorded{edPub, mlPub}
	}
	known := map[string]recorded{}
	for _, id := range v["recorded"].([]any) {
		known[id.(string)] = pub[id.(string)]
	}
	approver := pub[v["keys"].(map[string]any)["approver"].(map[string]any)["keyId"].(string)]
	n := 0
	for _, raw := range v["accepted"].([]any) {
		c := raw.(map[string]any)
		label, object := c["label"].(string), c["object"].(map[string]any)
		msg := signedBytes(label, object)
		check(hex.EncodeToString(msg) == c["signedBytesHex"], "%s: signed bytes", c["name"])
		for _, item := range object["signatures"].([]any) {
			s := item.(map[string]any)
			k := keys[s["keyId"].(string)]
			var want []byte
			if s["alg"] == "ed25519" {
				want = ed25519.Sign(k.ed, msg)
			} else {
				want = must(k.ml.SignDeterministic(msg, &mldsa.Options{Context: label}))
			}
			check(bytes.Equal(want, b64(s["sig"])), "%s: %s signature is not the deterministic one", c["name"], s["alg"])
		}
		check(accepts(label, object, known, approver), "%s: not accepted", c["name"])
		n++
	}
	for _, raw := range v["rejected"].([]any) {
		c := raw.(map[string]any)
		check(!accepts(c["label"].(string), c["object"].(map[string]any), known, approver), "%s: accepted", c["name"])
		n++
	}
	return n
}

// ---- the approval link ----------------------------------------------------

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func hkdf2(ck, ikm []byte) ([]byte, []byte) {
	t := hmacSHA256(ck, ikm)
	o1 := hmacSHA256(t, []byte{1})
	o2 := hmacSHA256(t, append(append([]byte{}, o1...), 2))
	return o1, o2
}

func nonce(n uint64) []byte {
	out := make([]byte, 12)
	binary.LittleEndian.PutUint64(out[4:], n)
	return out
}

func seal(k []byte, n uint64, ad, p []byte) []byte {
	return aeadSeal(k, nonce(n), ad, p)
}

func open(k []byte, n uint64, ad, c []byte) ([]byte, error) {
	return aeadOpen(k, nonce(n), ad, c)
}

type symmetric struct {
	h, ck, k []byte
	n        uint64
}

func newSymmetric(name string) *symmetric {
	h := sha256.Sum256([]byte(name))
	return &symmetric{h: h[:], ck: h[:]}
}

func (s *symmetric) mixHash(d []byte) {
	h := sha256.Sum256(append(append([]byte{}, s.h...), d...))
	s.h = h[:]
}

func (s *symmetric) mixKey(ikm []byte) { s.ck, s.k = hkdf2(s.ck, ikm); s.n = 0 }

func (s *symmetric) encrypt(p []byte) []byte {
	c := seal(s.k, s.n, s.h, p)
	s.n++
	s.mixHash(c)
	return c
}

func (s *symmetric) decrypt(c []byte) ([]byte, error) {
	p, err := open(s.k, s.n, s.h, c)
	s.n++
	if err != nil {
		return nil, err
	}
	s.mixHash(c)
	return p, nil
}

func dh(priv *ecdh.PrivateKey, pub []byte) ([]byte, error) {
	pk, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	out, err := priv.ECDH(pk) // Go refuses an all-zero result itself
	if err != nil {
		return nil, errors.New("low-order X25519 point")
	}
	return out, nil
}

type side struct {
	x  *ecdh.PrivateKey
	xp []byte
	k  *mlkem.DecapsulationKey768
}

func sideFrom(m map[string]any) side {
	x := must(ecdh.X25519().NewPrivateKey(b64(m["x25519Seed"])))
	k := must(mlkem.NewDecapsulationKey768(b64(m["mlKem768Seed"])))
	check(bytes.Equal(x.PublicKey().Bytes(), b64(m["x25519Public"])), "link: X25519 public")
	check(bytes.Equal(k.EncapsulationKey().Bytes(), b64(m["mlKem768Public"])), "link: ML-KEM public")
	return side{x, x.PublicKey().Bytes(), k}
}

func mixStatics(s *symmetric, i, r side) {
	s.mixHash(i.xp)
	s.mixHash(i.k.EncapsulationKey().Bytes())
	s.mixHash(r.xp)
	s.mixHash(r.k.EncapsulationKey().Bytes())
}

// respond runs the host's reading of message 1 with the approver's statics
// expected to be ia; it returns the state or the failure.
func respond(name string, ia, host side, m1 []byte) (*symmetric, []byte, []byte, error) {
	const fixed = 32 + 1184 + 1088
	if len(m1) < fixed+16 {
		return nil, nil, nil, errors.New("message 1 length")
	}
	s := newSymmetric(name)
	mixStatics(s, ia, host)
	re, rek, c := m1[:32], m1[32:32+1184], m1[32+1184:fixed]
	s.mixHash(re)
	s.mixHash(rek)
	es, err := dh(host.x, re)
	if err != nil {
		return nil, nil, nil, err
	}
	s.mixKey(es)
	ss := must(dh(host.x, ia.xp))
	s.mixKey(ss)
	s.mixHash(c)
	s.mixKey(must(host.k.Decapsulate(c)))
	_, err = s.decrypt(m1[fixed:])
	return s, re, rek, err
}

func checkLink(v map[string]any) int {
	name := v["protocolName"].(string)
	approver := sideFrom(v["approver"].(map[string]any))
	host := sideFrom(v["host"].(map[string]any))
	ar, hr := v["approverRandom"].(map[string]any), v["hostRandom"].(map[string]any)
	p1 := plaintextOf(v["payload1Text"], v["payload1"], "payload 1")
	p2 := plaintextOf(v["payload2Text"], v["payload2"], "payload 2")

	// Message 1, written by the approver.
	i := newSymmetric(name)
	mixStatics(i, approver, host)
	e := must(ecdh.X25519().NewPrivateKey(b64(ar["ephemeralX25519Seed"])))
	ek := must(mlkem.NewDecapsulationKey768(b64(ar["ephemeralMlKem768Seed"])))
	i.mixHash(e.PublicKey().Bytes())
	i.mixHash(ek.EncapsulationKey().Bytes())
	i.mixKey(must(dh(e, host.xp)))
	i.mixKey(must(dh(approver.x, host.xp)))
	k0, c0 := must2(mlkemtest.Encapsulate768(host.k.EncapsulationKey(), b64(ar["coinsToHostStatic"])))
	i.mixHash(c0)
	i.mixKey(k0)
	m1 := append(append(append(append([]byte{}, e.PublicKey().Bytes()...), ek.EncapsulationKey().Bytes()...), c0...), i.encrypt(p1)...)
	check(hex.EncodeToString(m1) == v["message1Hex"], "message 1")
	check(hex.EncodeToString(append(binary.BigEndian.AppendUint32(nil, uint32(len(m1))), m1...)) == v["message1FrameHex"], "message 1 frame")
	check(hex.EncodeToString(i.h) == v["handshakeHashAfterMessage1"], "h after message 1")

	// Read by the host, then message 2.
	r, re, rek, err := respond(name, approver, host, m1)
	check(err == nil && bytes.Equal(r.h, i.h), "host reads message 1")
	he := must(ecdh.X25519().NewPrivateKey(b64(hr["ephemeralX25519Seed"])))
	r.mixHash(he.PublicKey().Bytes())
	r.mixKey(must(dh(he, re)))
	r.mixKey(must(dh(he, approver.xp)))
	k1, c1 := must2(mlkemtest.Encapsulate768(must(mlkem.NewEncapsulationKey768(rek)), b64(hr["coinsToApproverEphemeral"])))
	r.mixHash(c1)
	r.mixKey(k1)
	k2, c2 := must2(mlkemtest.Encapsulate768(approver.k.EncapsulationKey(), b64(hr["coinsToApproverStatic"])))
	r.mixHash(c2)
	r.mixKey(k2)
	m2 := append(append(append(append([]byte{}, he.PublicKey().Bytes()...), c1...), c2...), r.encrypt(p2)...)
	check(hex.EncodeToString(m2) == v["message2Hex"], "message 2")
	check(hex.EncodeToString(append(binary.BigEndian.AppendUint32(nil, uint32(len(m2))), m2...)) == v["message2FrameHex"], "message 2 frame")
	hI2R, hR2I := hkdf2(r.ck, nil)

	// Read by the approver.
	i.mixHash(m2[:32])
	i.mixKey(must(dh(e, m2[:32])))
	i.mixKey(must(dh(approver.x, m2[:32])))
	i.mixHash(m2[32 : 32+1088])
	i.mixKey(must(ek.Decapsulate(m2[32 : 32+1088])))
	i.mixHash(m2[32+1088 : 32+2*1088])
	i.mixKey(must(approver.k.Decapsulate(m2[32+1088 : 32+2*1088])))
	got2, err := i.decrypt(m2[32+2*1088:])
	check(err == nil && bytes.Equal(got2, p2), "approver reads message 2")
	aI2R, aR2I := hkdf2(i.ck, nil)
	check(bytes.Equal(aI2R, hI2R) && bytes.Equal(aR2I, hR2I) && bytes.Equal(i.h, r.h), "both sides agree")
	check(hex.EncodeToString(r.h) == v["handshakeHash"], "handshake hash")
	check(hex.EncodeToString(hI2R) == v["approverToHostKey"], "approver-to-host key")
	check(hex.EncodeToString(hR2I) == v["hostToApproverKey"], "host-to-approver key")

	// Transport.
	keys := map[string][]byte{"approver": hI2R, "host": hR2I}
	counters := map[string]uint64{}
	n := 0
	for _, raw := range v["transport"].([]any) {
		f := raw.(map[string]any)
		from := f["from"].(string)
		plain := plaintextOf(f["plaintext"], f["json"], fmt.Sprintf("frame %d", n))
		check(uint64(f["n"].(float64)) == counters[from], "frame %d: counter", n)
		c := seal(keys[from], counters[from], nil, plain)
		counters[from]++
		check(hex.EncodeToString(c) == f["ciphertextHex"], "frame %d (%s): ciphertext", n, f["json"].(map[string]any)["op"])
		check(hex.EncodeToString(append(binary.BigEndian.AppendUint32(nil, uint32(len(c))), c...)) == f["frameHex"], "frame %d: frame", n)
		if f["json"].(map[string]any)["op"] == "rekey" {
			all := seal(keys[from], ^uint64(0), nil, make([]byte, 32))
			keys[from] = all[:32]
			check(hex.EncodeToString(keys[from]) == f["keyAfterRekeyHex"], "frame %d: key after rekey", n)
		}
		n++
	}

	// Failures: an altered byte of the payload, of the ML-KEM ciphertext, a
	// truncated message 1, an unknown approver.
	alt := append([]byte{}, m1...)
	alt[len(alt)-1] ^= 1
	_, _, _, err = respond(name, approver, host, alt)
	check(err != nil, "altered message 1 accepted")
	alt = append([]byte{}, m1...)
	alt[32+1184+10] ^= 1
	_, _, _, err = respond(name, approver, host, alt)
	check(err != nil, "altered ML-KEM ciphertext accepted")
	_, _, _, err = respond(name, approver, host, m1[:2000])
	check(err != nil, "truncated message 1 accepted")
	other := side{must(ecdh.X25519().NewPrivateKey(make([]byte, 32))), nil, approver.k}
	other.xp = other.x.PublicKey().Bytes()
	_, _, _, err = respond(name, other, host, m1)
	check(err != nil, "message 1 accepted with other recorded approver keys")
	return n
}

// plaintextOf returns the exact text of a message and checks that it is the
// JSON beside it (member order is the writer's; JSON readers ignore it).
func plaintextOf(text, parsed any, what string) []byte {
	var back any
	if err := json.Unmarshal([]byte(text.(string)), &back); err != nil {
		check(false, "%s: not JSON", what)
	}
	check(fmt.Sprint(back) == fmt.Sprint(parsed), "%s: text is not its json", what)
	return []byte(text.(string))
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func list(items []any) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(items)))
	for _, it := range items {
		out = append(out, lps(it.(string))...)
	}
	return out
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// checkCodes recomputes approval_codes.json's request digests (from the
// canonical references it lists), codes and tokens.
func checkCodes(v map[string]any) int {
	n := 0
	for _, raw := range v["codes"].([]any) {
		c := raw.(map[string]any)
		id := c["identity"].(map[string]any)
		uid := fmt.Sprint(id["uid"])
		if f, ok := id["uid"].(float64); ok {
			uid = fmt.Sprintf("%d", int64(f))
		}
		data := lps("tsm-approval-request-v1")
		for _, k := range []string{"kind", "exe", "interpreter", "script", "cwd"} {
			data = append(data, lps(str(id, k))...)
		}
		data = append(data, lps(uid)...)
		data = append(data, list(id["args"].([]any))...)
		data = append(data, list(c["canonicalRefs"].([]any))...)
		digest := sha256.Sum256(data)
		check(hex.EncodeToString(digest[:]) == c["requestDigestHex"], "%s: request digest", c["name"])
		h := sha256.Sum256(append(append(append(lps("tsm-approval-code-v1"), lps(c["host"].(string))...),
			lps(c["approvalId"].(string))...), digest[:]...))
		code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:])[:10]
		check(code == c["code"], "%s: code", c["name"])
		n++
	}
	for _, raw := range v["tokens"].([]any) {
		t := raw.(map[string]any)
		in := append(append(append(lps("tsm-code-token-v1"), lps(t["host"].(string))...),
			lps(t["code"].(string))...), lps(t["decision"].(string))...)
		check(hex.EncodeToString(in) == t["tagInputHex"], "token %s %s: input", t["code"], t["decision"])
		tag := hmacSHA256(b64(t["tokenKey"]), in)[:16]
		token := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(tag)
		check(token == t["token"], "token %s %s", t["code"], t["decision"])
		n++
	}
	return n
}

func main() {
	selfTestAEAD()
	dir := filepath.Join("..", "..", "vectors")
	codes := checkCodes(load(dir, "approval_codes.json"))
	sigs := checkSignatures(load(dir, "signatures.json"))
	frames := checkLink(load(dir, "link_handshake.json"))
	for _, f := range failures {
		fmt.Println("FAIL", f)
	}
	status := "OK"
	if len(failures) > 0 {
		status = fmt.Sprintf("%d failure(s)", len(failures))
	}
	fmt.Printf("%d approval codes and tokens, %d signature cases, link handshake and %d transport frames: %s\n",
		codes, sigs, frames, status)
	if len(failures) > 0 {
		os.Exit(1)
	}
}
