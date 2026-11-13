// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package main

// ChaCha20-Poly1305 (RFC 8439) written out here, so the cross-check needs
// nothing beyond Go's standard library (which keeps its ChaCha20-Poly1305
// internal). selfTestAEAD checks it against the RFC's own vector first.

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"math/bits"
)

func quarterRound(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 16)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 12)
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 8)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 7)
}

func chachaBlock(key []byte, counter uint32, nonce []byte) []byte {
	var s, w [16]uint32
	s[0], s[1], s[2], s[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	s[12] = counter
	for i := 0; i < 3; i++ {
		s[13+i] = binary.LittleEndian.Uint32(nonce[4*i:])
	}
	w = s
	for i := 0; i < 10; i++ {
		quarterRound(&w, 0, 4, 8, 12)
		quarterRound(&w, 1, 5, 9, 13)
		quarterRound(&w, 2, 6, 10, 14)
		quarterRound(&w, 3, 7, 11, 15)
		quarterRound(&w, 0, 5, 10, 15)
		quarterRound(&w, 1, 6, 11, 12)
		quarterRound(&w, 2, 7, 8, 13)
		quarterRound(&w, 3, 4, 9, 14)
	}
	out := make([]byte, 64)
	for i := range w {
		binary.LittleEndian.PutUint32(out[4*i:], w[i]+s[i])
	}
	return out
}

func chachaXor(key []byte, counter uint32, nonce, in []byte) []byte {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i += 64 {
		block := chachaBlock(key, counter+uint32(i/64), nonce)
		for j := i; j < len(in) && j < i+64; j++ {
			out[j] = in[j] ^ block[j-i]
		}
	}
	return out
}

func leInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func poly1305(key, msg []byte) []byte {
	rb := append([]byte{}, key[:16]...)
	for _, i := range []int{3, 7, 11, 15} {
		rb[i] &= 15
	}
	for _, i := range []int{4, 8, 12} {
		rb[i] &= 252
	}
	r, s := leInt(rb), leInt(key[16:32])
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	acc := new(big.Int)
	for i := 0; i < len(msg); i += 16 {
		end := min(i+16, len(msg))
		n := leInt(append(append([]byte{}, msg[i:end]...), 1))
		acc.Add(acc, n).Mul(acc, r).Mod(acc, p)
	}
	acc.Add(acc, s)
	tag := make([]byte, 16)
	be := acc.Bytes()
	for i := 0; i < 16 && i < len(be); i++ {
		tag[i] = be[len(be)-1-i]
	}
	return tag
}

func pad16(b []byte) []byte { return append(b, make([]byte, (16-len(b)%16)%16)...) }

func aeadTag(key, nonce, ad, ciphertext []byte) []byte {
	polyKey := chachaBlock(key, 0, nonce)[:32]
	data := pad16(append([]byte{}, ad...))
	data = append(data, pad16(append([]byte{}, ciphertext...))...)
	data = binary.LittleEndian.AppendUint64(data, uint64(len(ad)))
	data = binary.LittleEndian.AppendUint64(data, uint64(len(ciphertext)))
	return poly1305(polyKey, data)
}

func aeadSeal(key, nonce, ad, plaintext []byte) []byte {
	c := chachaXor(key, 1, nonce, plaintext)
	return append(c, aeadTag(key, nonce, ad, c)...)
}

func aeadOpen(key, nonce, ad, sealed []byte) ([]byte, error) {
	if len(sealed) < 16 {
		return nil, errors.New("short ciphertext")
	}
	c, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	if subtle.ConstantTimeCompare(tag, aeadTag(key, nonce, ad, c)) != 1 {
		return nil, errors.New("does not decrypt")
	}
	return chachaXor(key, 1, nonce, c), nil
}

// selfTestAEAD is RFC 8439 section 2.8.2.
func selfTestAEAD() {
	key, _ := hex.DecodeString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce, _ := hex.DecodeString("070000004041424344454647")
	ad, _ := hex.DecodeString("50515253c0c1c2c3c4c5c6c7")
	plain := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	want, _ := hex.DecodeString("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116" + "1ae10b594f09e26a7e902ecbd0600691")
	got := aeadSeal(key, nonce, ad, plain)
	back, err := aeadOpen(key, nonce, ad, got)
	if !bytes.Equal(got, want) || err != nil || !bytes.Equal(back, plain) {
		panic("ChaCha20-Poly1305 does not reproduce RFC 8439 section 2.8.2")
	}
}
