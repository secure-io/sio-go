// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"
)

func TestVectorWrite(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range TestVectors {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.newWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		dw := stream.DecryptWriter(plaintext, test.Nonce, test.AssociatedData)
		if _, err = dw.Write(test.Ciphertext); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}
		if err = dw.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close DecWriter: %v", i, err)
		}
		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}

		ew := stream.EncryptWriter(ciphertext, test.Nonce, test.AssociatedData)
		if _, err = ew.Write(test.Plaintext); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}
		if err = ew.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close EncWriter: %v", i, err)
		}
		if !bytes.Equal(ciphertext.Bytes(), test.Ciphertext) {
			t.Fatalf("Test %d: ciphertext does not match original plaintext", i)
		}
	}
}

func TestVectorWriteByte(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range TestVectors {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.newWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		dw := stream.DecryptWriter(plaintext, test.Nonce, test.AssociatedData)
		if err = copyBytes(dw, bytes.NewReader(test.Ciphertext)); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}
		if err = dw.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close DecWriter: %v", i, err)
		}
		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}

		ew := stream.EncryptWriter(ciphertext, test.Nonce, test.AssociatedData)
		if err = copyBytes(ew, bytes.NewReader(test.Plaintext)); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}
		if err = ew.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close EncWriter: %v", i, err)
		}
		if !bytes.Equal(ciphertext.Bytes(), test.Ciphertext) {
			t.Fatalf("Test %d: ciphertext does not match original plaintext", i)
		}
	}
}

func TestVectorReadFrom(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range TestVectors {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.newWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		dw := stream.DecryptWriter(plaintext, test.Nonce, test.AssociatedData)
		if _, err = dw.ReadFrom(bytes.NewReader(test.Ciphertext)); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}
		if err = dw.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close DecWriter: %v", i, err)
		}
		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}

		ew := stream.EncryptWriter(ciphertext, test.Nonce, test.AssociatedData)
		if _, err = ew.ReadFrom(bytes.NewReader(test.Plaintext)); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}
		if err = ew.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close EncWriter: %v", i, err)
		}
		if !bytes.Equal(ciphertext.Bytes(), test.Ciphertext) {
			t.Fatalf("Test %d: ciphertext does not match original plaintext", i)
		}
	}
}

func TestSimpleWrite(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range SimpleTests {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.newWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		ew := stream.EncryptWriter(ciphertext, test.Nonce, test.AssociatedData)
		if _, err = ew.Write(test.Plaintext); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}
		if err = ew.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close EncWriter: %v", i, err)
		}

		dw := stream.DecryptWriter(plaintext, test.Nonce, test.AssociatedData)
		if _, err = dw.Write(ciphertext.Bytes()); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}
		if err = dw.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close DecWriter: %v", i, err)
		}

		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}
	}
}

func TestSimpleWriteByte(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range SimpleTests {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.newWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		ew := stream.EncryptWriter(ciphertext, test.Nonce, test.AssociatedData)
		if err = copyBytes(ew, bytes.NewReader(test.Plaintext)); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}
		if err = ew.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close EncWriter: %v", i, err)
		}

		dw := stream.DecryptWriter(plaintext, test.Nonce, test.AssociatedData)
		if err = copyBytes(dw, ciphertext); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}
		if err = dw.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close DecWriter: %v", i, err)
		}

		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}
	}
}

func TestSimpleReadFrom(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range SimpleTests {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.newWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		ew := stream.EncryptWriter(ciphertext, test.Nonce, test.AssociatedData)
		if _, err = ew.ReadFrom(bytes.NewReader(test.Plaintext)); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}
		if err = ew.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close EncWriter: %v", i, err)
		}

		dw := stream.DecryptWriter(plaintext, test.Nonce, test.AssociatedData)
		if _, err = dw.ReadFrom(ciphertext); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}
		if err = dw.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close DecWriter: %v", i, err)
		}

		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}
	}
}

func TestWriteAfterClose(t *testing.T) {
	shouldPanicOnWrite := func(context string, w io.Writer, t *testing.T) {
		defer func() {
			if err := recover(); err == nil {
				t.Fatalf("%sWriter did not panic", context)
			}
		}()
		w.Write(nil)
	}

	s, err := AES_128_GCM.New(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create new Stream: %v", err)
	}
	nonce := make([]byte, s.NonceSize())
	dw := s.DecryptWriter(ioutil.Discard, nonce, nil)
	ew := s.EncryptWriter(dw, nonce, nil)
	if err := ew.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	shouldPanicOnWrite("Enc", ew, t)
	shouldPanicOnWrite("Dec", dw, t)
}

func TestWriteByteAfterClose(t *testing.T) {
	shouldPanicOnWrite := func(context string, w io.ByteWriter, t *testing.T) {
		defer func() {
			if err := recover(); err == nil {
				t.Fatalf("%sWriter did not panic", context)
			}
		}()
		w.WriteByte(0)
	}

	s, err := AES_128_GCM.New(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create new Stream: %v", err)
	}
	nonce := make([]byte, s.NonceSize())
	dw := s.DecryptWriter(ioutil.Discard, nonce, nil)
	ew := s.EncryptWriter(dw, nonce, nil)
	if err := ew.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	shouldPanicOnWrite("Enc", ew, t)
	shouldPanicOnWrite("Dec", dw, t)
}
func TestReadFromAfterClose(t *testing.T) {
	shouldPanicOnReadFrom := func(context string, w io.ReaderFrom, t *testing.T) {
		defer func() {
			if err := recover(); err == nil {
				t.Fatalf("%sWriter did not panic", context)
			}
		}()
		w.ReadFrom(bytes.NewReader(nil))
	}

	s, err := AES_128_GCM.New(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create new Stream: %v", err)
	}
	nonce := make([]byte, s.NonceSize())
	dw := s.DecryptWriter(ioutil.Discard, nonce, nil)
	ew := s.EncryptWriter(dw, nonce, nil)
	if err := ew.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	shouldPanicOnReadFrom("Enc", ew, t)
	shouldPanicOnReadFrom("Dec", dw, t)
}
