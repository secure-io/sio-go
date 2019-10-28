// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package sioutil implements some I/O utility functions.
package sioutil

import (
	"io"

	"golang.org/x/sys/cpu"
)

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }

// NopCloser returns a WriteCloser that wraps w
// and implements Close as a no-op.
func NopCloser(w io.Writer) io.WriteCloser {
	return nopCloser{w}
}

// NativeAES returns true when the executing CPU
// provides AES-GCM hardware instructions and
// an optimized assembler implementation is
// available.
//
// It is strongly recommended to only use AES-GCM
// when NativeAES() returns true. Otherwise, the
// AES-GCM implementation may be vulnerable to
// timing attacks.
// See: https://golang.org/pkg/crypto/aes
func NativeAES() bool {
	if cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ {
		return true
	}
	if cpu.ARM64.HasAES {
		return true
	}

	// On s390x, aes.NewCipher(...) returns a type
	// that provides AES asm implementations only
	// if all (CBC, CTR and GCM) AES hardware
	// instructions are available.
	// See: https://golang.org/src/crypto/aes/cipher_s390x.go#L39
	return cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR &&
		(cpu.S390X.HasAESGCM || cpu.S390X.HasGHASH)
}
