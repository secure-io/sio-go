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

func TestWrite(t *testing.T) {
	s := NewStream(AES128GCM, BufferSize())

	data := make([]byte, PlaintextSize())
	nonce := make([]byte, s.NonceSize())
	associatedData := make([]byte, 32)

	plaintext := bytes.NewBuffer(make([]byte, 0, len(data)))
	ciphertext := bytes.NewBuffer(make([]byte, 0, int64(len(data))+s.Overhead(int64(len(data)))))

	ew := s.EncryptWriter(ciphertext, nonce, associatedData)
	dw := s.DecryptWriter(plaintext, nonce, associatedData)

	half := len(data) / 2
	if n, err := ew.Write(data[:half]); err != nil || n != half {
		t.Fatalf("Write failed: got %d - want %d err: %v", n, half, err)
	}
	if n, err := ew.Write(data[half:]); err != nil || n != len(data)-half {
		t.Fatalf("Write failed: got %d - want %d err: %v", n, len(data)-half, err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	half = len(ciphertext.Bytes()) / 2
	if n, err := dw.Write(ciphertext.Bytes()[:half]); err != nil || n != half {
		t.Fatalf("Write failed: got %d - want %d err: %v", n, half, err)
	}
	if n, err := dw.Write(ciphertext.Bytes()[half:]); err != nil || n != len(ciphertext.Bytes())-half {
		t.Fatalf("Write failed: got %d - want %d err: %v", n, len(ciphertext.Bytes())-half, err)
	}
	if err := dw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if p := plaintext.Bytes(); !bytes.Equal(p, data) {
		t.Fatal("Decrypted data does not match the plaintext")
	}
}

func TestWriteByte(t *testing.T) {
	s := NewStream(AES128GCM, BufferSize())
	data := make([]byte, PlaintextSize())
	nonce := make([]byte, s.NonceSize())
	associatedData := make([]byte, 32)

	plaintext := bytes.NewBuffer(make([]byte, 0, len(data)))
	ciphertext := bytes.NewBuffer(make([]byte, 0, len(data)))

	ew := s.EncryptWriter(ciphertext, nonce, associatedData)
	for i, b := range data {
		if err := ew.WriteByte(b); err != nil {
			t.Fatalf("WriteByte failed at byte %d with: %v", i, err)
		}
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	dw := s.DecryptWriter(plaintext, nonce, associatedData)
	for i, b := range ciphertext.Bytes() {
		if err := dw.WriteByte(b); err != nil {
			t.Fatalf("WriteByte failed at byte %d with: %v", i, err)
		}
	}
	if err := dw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if p := plaintext.Bytes(); !bytes.Equal(p, data) {
		t.Fatal("Decrypted data does not match plaintext")
	}
}

func TestReadFrom(t *testing.T) {
	s := NewStream(AES128GCM, BufferSize())
	data := make([]byte, PlaintextSize())
	nonce := make([]byte, s.NonceSize())
	associatedData := make([]byte, 32)

	plaintext := bytes.NewBuffer(make([]byte, 0, len(data)))
	ciphertext := bytes.NewBuffer(make([]byte, 0, int64(len(data))+s.Overhead(int64(len(data)))))
	sw := s.EncryptWriter(ciphertext, nonce, associatedData)
	ow := s.DecryptWriter(plaintext, nonce, associatedData)

	if n, err := sw.ReadFrom(bytes.NewReader(data)); err != nil || n != int64(len(data)) {
		t.Fatalf("ReadFrom failed: got %d - want %d err: %v", n, int64(len(data)), err)
	}
	if !sw.closed {
		t.Fatal("EncWriter wasn't closed by ReadFrom")
	}

	ctLen := int64(ciphertext.Len())
	if n, err := ow.ReadFrom(ciphertext); err != nil || n != ctLen {
		t.Fatalf("ReadFrom failed: got %d - want %d err: %v", n, ctLen, err)
	}
	if !ow.closed {
		t.Fatal("DecWriter wasn't closed by ReadFrom")
	}

	if p := plaintext.Bytes(); !bytes.Equal(p, data) {
		t.Fatal("Decrypted data does not match the plaintext")
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

	s := NewStream(AES128GCM, BufferSize())
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

	s := NewStream(AES128GCM, BufferSize())
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

	s := NewStream(AES128GCM, BufferSize())
	nonce := make([]byte, s.NonceSize())
	dw := s.DecryptWriter(ioutil.Discard, nonce, nil)
	ew := s.EncryptWriter(dw, nonce, nil)
	if err := ew.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	shouldPanicOnReadFrom("Enc", ew, t)
	shouldPanicOnReadFrom("Dec", dw, t)
}
