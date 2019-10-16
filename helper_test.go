// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio

import (
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"os"
)

func init() {
	flag.Int64Var(&testBufSize, "sio.BufSize", BufSize/1024, "The buffer size for tests and benchmarks in KiB")
	flag.Int64Var(&testPlaintextSize, "sio.PlaintextSize", 1024, "The plaintext size for tests in KiB")

	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(fmt.Sprintf("Failed to create AES: %v", err))
	}
	AES128GCM, err = cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("Failed to create AES-GCM: %v", err))
	}
}

var (
	testBufSize       int64
	testPlaintextSize int64

	AES128GCM cipher.AEAD
	DevNull   = devNull{}
)

func BufferSize() int {
	if !flag.Parsed() {
		fmt.Fprintf(os.Stderr, "sio: BufferSize() called before flag.Parse\n")
		os.Exit(2)
	}
	return int(testBufSize) * 1024
}

func PlaintextSize() int {
	if !flag.Parsed() {
		fmt.Fprintf(os.Stderr, "sio: BufferSize() called before flag.Parse\n")
		os.Exit(2)
	}
	return int(testPlaintextSize) * 1024
}

type devNull struct{}

func (devNull) Read(p []byte) (int, error)  { return len(p), nil }
func (devNull) Write(p []byte) (int, error) { return len(p), nil }
