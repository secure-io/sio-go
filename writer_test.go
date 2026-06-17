// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio

import (
	"bytes"
	"io"
	"testing"
)

func TestVectorWrite(t *testing.T) {
	ciphertext := bytes.NewBuffer(nil)
	plaintext := bytes.NewBuffer(nil)

	for i, test := range TestVectors {
		ciphertext.Reset()
		plaintext.Reset()

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
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

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
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

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
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

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
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

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
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

		stream, err := test.Algorithm.streamWithBufSize(test.Key, test.BufSize)
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

// TestBlockNumDecryptWriter verifies that DecryptWriter with blockNum = t
// decrypts the ciphertext suffix starting at block t into the plaintext
// suffix starting at t*bufSize. See blockNumTests in reader_test.go for the
// semantics of the blockNum parameter.
func TestBlockNumDecryptWriter(t *testing.T) {
	for i, tc := range blockNumTests {
		stream, nonce, ad, plaintext, ciphertext := newBlockNumCase(t, tc)

		blockSize := stream.bufSize + stream.cipher.Overhead()
		for cipherOff, blk := 0, 0; cipherOff < len(ciphertext); cipherOff, blk = cipherOff+blockSize, blk+1 {
			plainOff := blk * stream.bufSize

			out := new(bytes.Buffer)
			dw := stream.DecryptWriter(out, nonce, ad)
			dw.Reset(uint32(blk))
			if _, err := dw.Write(ciphertext[cipherOff:]); err != nil {
				t.Fatalf("Test %d: block %d: failed to write ciphertext: %v", i, blk, err)
			}
			if err := dw.Close(); err != nil {
				t.Fatalf("Test %d: block %d: failed to close: %v", i, blk, err)
			}
			if want := plaintext[plainOff:]; !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("Test %d: block %d: plaintext mismatch: got %d bytes, want %d bytes", i, blk, out.Len(), len(want))
			}
		}
	}
}

// TestBlockNumEncryptWriter verifies that EncryptWriter with blockNum = t
// produces exactly the ciphertext suffix starting at block t, i.e. the same
// bytes a full encryption (blockNum = 0) would emit from block t onwards.
func TestBlockNumEncryptWriter(t *testing.T) {
	for i, tc := range blockNumTests {
		stream, nonce, ad, plaintext, ciphertext := newBlockNumCase(t, tc)

		blockSize := stream.bufSize + stream.cipher.Overhead()
		for cipherOff, blk := 0, 0; cipherOff < len(ciphertext); cipherOff, blk = cipherOff+blockSize, blk+1 {
			plainOff := blk * stream.bufSize

			out := new(bytes.Buffer)
			ew := stream.EncryptWriter(out, nonce, ad)
			ew.Reset(uint32(blk))
			if _, err := ew.Write(plaintext[plainOff:]); err != nil {
				t.Fatalf("Test %d: block %d: failed to write plaintext: %v", i, blk, err)
			}
			if err := ew.Close(); err != nil {
				t.Fatalf("Test %d: block %d: failed to close: %v", i, blk, err)
			}
			if want := ciphertext[cipherOff:]; !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("Test %d: block %d: ciphertext mismatch: got %d bytes, want %d bytes", i, blk, out.Len(), len(want))
			}
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

	s, err := AES_128_GCM.Stream(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create new Stream: %v", err)
	}
	nonce := make([]byte, s.NonceSize())
	dw := s.DecryptWriter(io.Discard, nonce, nil)
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

	s, err := AES_128_GCM.Stream(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create new Stream: %v", err)
	}
	nonce := make([]byte, s.NonceSize())
	dw := s.DecryptWriter(io.Discard, nonce, nil)
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

	s, err := AES_128_GCM.Stream(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create new Stream: %v", err)
	}
	nonce := make([]byte, s.NonceSize())
	dw := s.DecryptWriter(io.Discard, nonce, nil)
	ew := s.EncryptWriter(dw, nonce, nil)
	if err := ew.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	shouldPanicOnReadFrom("Enc", ew, t)
	shouldPanicOnReadFrom("Dec", dw, t)
}
