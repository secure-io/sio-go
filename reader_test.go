// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio

import (
	"bytes"
	"io"
	"testing"
)

func TestRead(t *testing.T) {
	s := NewStream(AES128GCM, BufferSize())
	data := make([]byte, PlaintextSize())
	nonce := make([]byte, s.NonceSize())
	associatedData := make([]byte, 32)

	plaintext := make([]byte, len(data))
	ciphertext := make([]byte, int64(len(data))+s.Overhead(int64(len(data))))

	er := s.EncryptReader(bytes.NewReader(data), nonce, associatedData)
	if _, err := io.ReadFull(er, ciphertext[:len(ciphertext)/2]); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if _, err := io.ReadFull(er, ciphertext[len(ciphertext)/2:]); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	dr := s.DecryptReader(bytes.NewReader(ciphertext), nonce, associatedData)
	if _, err := io.ReadFull(dr, plaintext[:len(plaintext)/2]); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if _, err := io.ReadFull(dr, plaintext[len(plaintext)/2:]); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(plaintext, data) {
		t.Fatal("Decrypted data does not match the plaintext")
	}
}

func TestReadByte(t *testing.T) {
	s := NewStream(AES128GCM, BufferSize())
	data := make([]byte, PlaintextSize())
	nonce := make([]byte, s.NonceSize())
	associatedData := make([]byte, 32)

	ciphertext := make([]byte, int64(len(data))+s.Overhead(int64(len(data))))
	er := s.EncryptReader(bytes.NewReader(data), nonce, associatedData)
	for i := range ciphertext {
		b, err := er.ReadByte()
		if err != nil {
			t.Fatalf("ReadByte failed at byte %d with: %v", i, err)
		}
		ciphertext[i] = b
	}
	if _, err := er.ReadByte(); err != io.EOF {
		t.Fatalf("ReadByte failed: got '%v' - want '%v'", err, io.EOF)
	}

	dr := s.DecryptReader(bytes.NewReader(ciphertext), nonce, associatedData)
	for i := range data {
		b, err := dr.ReadByte()
		if err != nil {
			t.Fatalf("ReadByte failed at byte %d with: %v", i, err)
		}
		if b != data[i] {
			t.Fatalf("Decrypted data does not match plaintext: got %x - want %x", b, data[i])
		}
	}
	if _, err := dr.ReadByte(); err != io.EOF {
		t.Fatalf("ReadByte failed: got '%v' - want '%v'", err, io.EOF)
	}
}

func TestWriteTo(t *testing.T) {
	s := NewStream(AES128GCM, BufferSize())
	data := make([]byte, PlaintextSize())
	nonce := make([]byte, s.NonceSize())
	associatedData := make([]byte, 32)

	sealedSize := int64(len(data)) + s.Overhead(int64(len(data)))
	plaintext := bytes.NewBuffer(make([]byte, 0, len(data)))
	ciphertext := bytes.NewBuffer(make([]byte, 0, sealedSize))

	er := s.EncryptReader(bytes.NewReader(data), nonce, associatedData)
	if n, err := er.WriteTo(ciphertext); err != nil || n != sealedSize {
		t.Fatalf("WriteTo failed: got %d - want %d err: %v", n, sealedSize, err)
	}

	dr := s.DecryptReader(ciphertext, nonce, associatedData)
	if n, err := dr.WriteTo(plaintext); err != nil || n != int64(len(data)) {
		t.Fatalf("ReadFrom failed: got %d - want %d err: %v", n, int64(len(data)), err)
	}

	if p := plaintext.Bytes(); !bytes.Equal(p, data) {
		t.Fatal("Decrypted data does not match the plaintext")
	}
}

func TestReadAt(t *testing.T) {
	s := NewStream(AES128GCM, BufferSize())
	data := make([]byte, PlaintextSize())
	nonce := make([]byte, s.NonceSize())
	associatedData := make([]byte, 32)

	half := len(data) / 2
	for i := range data[:half] {
		data[i] = 1
	}

	sealedSize := int64(len(data)) + s.Overhead(int64(len(data)))
	ciphertext := bytes.NewBuffer(make([]byte, 0, sealedSize))

	er := s.EncryptReader(bytes.NewReader(data), nonce, associatedData)
	if n, err := er.WriteTo(ciphertext); err != nil || n != sealedSize {
		t.Fatalf("WriteTo failed: got %d - want %d err: %v", n, sealedSize, err)
	}

	plaintext := make([]byte, len(data))
	dr := s.DecryptReaderAt(bytes.NewReader(ciphertext.Bytes()), nonce, associatedData)
	if n, err := dr.ReadAt(plaintext[:half], 0); err != nil || n != half {
		t.Fatalf("ReadAt failed: got %d - want %d err: %v", n, half, err)
	}
	if n, err := dr.ReadAt(plaintext[half:], int64(half)); err != nil || n != len(plaintext)-half {
		t.Fatalf("ReadAt failed: got %d - want %d err: %v", n, len(plaintext)-half, err)
	}

	if !bytes.Equal(plaintext, data) {
		t.Fatal("Decrypted data does not match the plaintext")
	}
}
