// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Package tsm is the Go client of the Tom Secrets Manager's secrets
// service. A program reads its secrets from the secrets service that runs
// for its user on the same machine:
//
//	c, err := tsm.Connect(ctx)
//	if err != nil { ... }
//	defer c.Close()
//	v, err := c.Get(ctx, "[env:prod]db.main", tsm.WithField("UserName"))
//	if err != nil { ... }
//	defer v.Close()
//	name, err := v.Text()
//
// Every failure from the service or about it is an [*Error] with a Kind
// ([ErrorKind]), used with errors.As; a cancelled context is the context's
// own error. A [Value] never prints its secret, and Close overwrites its
// buffer. The library is written from the protocol document (protocol.md),
// uses only the standard library and logs nothing.
package tsm
