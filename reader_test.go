// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio

import (
	"bytes"
	"io"
	"math"
	"testing"
)

func TestVectorRead(t *testing.T) {
	for i, test := range TestVectors {
		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}
		pLen := int64(len(test.Plaintext))

		plaintext := make([]byte, pLen)
		dr := stream.DecryptReader(bytes.NewReader(test.Ciphertext), test.Nonce, test.AssociatedData)
		if _, err = io.ReadFull(dr, plaintext); err != nil {
			t.Fatalf("Test: %d: Failed to decrypt ciphertext: %v", i, err)
		}

		if !bytes.Equal(plaintext, test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}

		ciphertext := make([]byte, pLen+stream.Overhead(pLen))
		er := stream.EncryptReader(bytes.NewReader(test.Plaintext), test.Nonce, test.AssociatedData)
		if _, err = io.ReadFull(er, ciphertext); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}

		if !bytes.Equal(ciphertext, test.Ciphertext) {
			t.Fatalf("Test %d: ciphertext does not match original ciphertext", i)
		}
	}
}

func TestVectorReadByte(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range TestVectors {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		dr := stream.DecryptReader(bytes.NewReader(test.Ciphertext), test.Nonce, test.AssociatedData)
		if err = copyBytes(plaintext, dr); err != nil {
			t.Fatalf("Test: %d: Failed to decrypt ciphertext: %v", i, err)
		}
		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}

		er := stream.EncryptReader(bytes.NewReader(test.Plaintext), test.Nonce, test.AssociatedData)
		if err = copyBytes(ciphertext, er); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}

		if !bytes.Equal(ciphertext.Bytes(), test.Ciphertext) {
			t.Fatalf("Test %d: ciphertext does not match original plaintext", i)
		}
	}
}

func TestVectorWriteTo(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range TestVectors {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		dr := stream.DecryptReader(bytes.NewReader(test.Ciphertext), test.Nonce, test.AssociatedData)
		if _, err = dr.WriteTo(plaintext); err != nil {
			t.Fatalf("Test: %d: Failed to decrypt ciphertext: %v", i, err)
		}
		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}

		er := stream.EncryptReader(bytes.NewReader(test.Plaintext), test.Nonce, test.AssociatedData)
		if _, err = er.WriteTo(ciphertext); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}

		if !bytes.Equal(ciphertext.Bytes(), test.Ciphertext) {
			t.Fatalf("Test %d: ciphertext does not match original plaintext", i)
		}
	}
}

func TestVectorReadAt(t *testing.T) {
	for i, test := range TestVectors {
		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}
		pLen := int64(len(test.Plaintext))

		plaintext := make([]byte, pLen)
		dr := stream.DecryptReaderAt(bytes.NewReader(test.Ciphertext), test.Nonce, test.AssociatedData)
		if _, err = dr.ReadAt(plaintext, 0); err != nil {
			t.Fatalf("Test: %d: Failed to decrypt ciphertext: %v", i, err)
		}

		if !bytes.Equal(plaintext, test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}
	}
}

func TestVectorReadAtSection(t *testing.T) {
	plaintext := bytes.NewBuffer(nil)

	for i, test := range TestVectors {
		plaintext.Reset()

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		dr := stream.DecryptReaderAt(bytes.NewReader(test.Ciphertext), test.Nonce, test.AssociatedData)
		r := io.NewSectionReader(dr, 0, math.MaxInt64) // Use max. int64 to ensure we reach the EOF of the underlying ciphertext stream
		if _, err = io.Copy(plaintext, r); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}

		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}
	}
}

func TestSimpleRead(t *testing.T) {
	for i, test := range SimpleTests {
		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}
		pLen := int64(len(test.Plaintext))

		ciphertext := make([]byte, pLen+stream.Overhead(pLen))
		er := stream.EncryptReader(bytes.NewReader(test.Plaintext), test.Nonce, test.AssociatedData)
		if _, err = io.ReadFull(er, ciphertext); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}

		plaintext := make([]byte, pLen)
		dr := stream.DecryptReader(bytes.NewReader(ciphertext), test.Nonce, test.AssociatedData)
		if _, err = io.ReadFull(dr, plaintext); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}

		if !bytes.Equal(plaintext, test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}
	}
}

func TestSimpleReadByte(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range SimpleTests {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		er := stream.EncryptReader(bytes.NewReader(test.Plaintext), test.Nonce, test.AssociatedData)
		if err = copyBytes(ciphertext, er); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}

		dr := stream.DecryptReader(bytes.NewReader(ciphertext.Bytes()), test.Nonce, test.AssociatedData)
		if err = copyBytes(plaintext, dr); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}

		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}
	}
}

func TestSimpleWriteTo(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range SimpleTests {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		er := stream.EncryptReader(bytes.NewReader(test.Plaintext), test.Nonce, test.AssociatedData)
		if _, err = er.WriteTo(ciphertext); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}

		dr := stream.DecryptReader(bytes.NewReader(ciphertext.Bytes()), test.Nonce, test.AssociatedData)
		if _, err = dr.WriteTo(plaintext); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}

		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}
	}
}

func TestSimpleReadAt(t *testing.T) {
	for i, test := range SimpleTests {
		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}
		pLen := int64(len(test.Plaintext))

		ciphertext := make([]byte, pLen+stream.Overhead(pLen))
		er := stream.EncryptReader(bytes.NewReader(test.Plaintext), test.Nonce, test.AssociatedData)
		if _, err = io.ReadFull(er, ciphertext); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}

		plaintext := make([]byte, pLen)
		dr := stream.DecryptReaderAt(bytes.NewReader(ciphertext), test.Nonce, test.AssociatedData)
		if _, err = dr.ReadAt(plaintext, 0); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}

		if !bytes.Equal(plaintext, test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}
	}
}

func TestSimpleReadAtSection(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range SimpleTests {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
		if err != nil {
			t.Fatalf("Test %d: Failed to create new Stream: %v", i, err)
		}

		er := stream.EncryptReader(bytes.NewReader(test.Plaintext), test.Nonce, test.AssociatedData)
		if _, err = io.Copy(ciphertext, er); err != nil {
			t.Fatalf("Test: %d: Failed to encrypt plaintext: %v", i, err)
		}

		dr := stream.DecryptReaderAt(bytes.NewReader(ciphertext.Bytes()), test.Nonce, test.AssociatedData)
		r := io.NewSectionReader(dr, 0, math.MaxInt64) // Use max. int64 to ensure we reach the EOF of the underlying ciphertext stream
		if _, err = io.Copy(plaintext, r); err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}

		if !bytes.Equal(plaintext.Bytes(), test.Plaintext) {
			t.Fatalf("Test %d: plaintext does not match original plaintext", i)
		}
	}
}
