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

// The blockNum parameter of the Encrypt/Decrypt Reader and Writer
// constructors selects the sequence number of the first block that is
// processed. Since a stream is encrypted block-by-block and block t
// (0-based) is sealed with sequence number 1+t, passing blockNum = 1+t
// allows a caller to seek into an encrypted stream at block boundaries:
// it processes the ciphertext starting at byte offset t*(bufSize+overhead)
// as if it were the t-th block of a stream that started at blockNum = 0.
//
// These cases are sized so that the encrypted stream spans several blocks
// (and include an exact-multiple and a single-block stream as edge cases).
type blockNumTest struct {
	Algorithm Algorithm
	KeyLen    int
	BufSize   int
	PlainLen  int
}

var blockNumTests = []blockNumTest{
	{Algorithm: AES_128_GCM, KeyLen: 128 / 8, BufSize: 64, PlainLen: 64*4 + 10},         // 5 blocks
	{Algorithm: AES_256_GCM, KeyLen: 256 / 8, BufSize: 80, PlainLen: 80 * 3},            // 3 blocks, exact multiple
	{Algorithm: ChaCha20Poly1305, KeyLen: 256 / 8, BufSize: 100, PlainLen: 501},         // 6 blocks
	{Algorithm: XChaCha20Poly1305, KeyLen: 256 / 8, BufSize: 128, PlainLen: 128*2 + 50}, // 3 blocks
	{Algorithm: AES_128_GCM, KeyLen: 128 / 8, BufSize: 256, PlainLen: 200},              // 1 block
}

// newBlockNumCase creates a Stream for the test case and encrypts a random
// plaintext from the beginning (blockNum = 0). It returns the stream, the
// nonce / associatedData used, the plaintext and the full ciphertext.
func newBlockNumCase(t *testing.T, tc blockNumTest) (stream *Stream, nonce, associatedData, plaintext, ciphertext []byte) {
	t.Helper()

	stream, err := tc.Algorithm.streamWithBufSize(random(tc.KeyLen), tc.BufSize)
	if err != nil {
		t.Fatalf("failed to create stream: %v", err)
	}
	nonce = random(stream.NonceSize())
	associatedData = random(32)
	plaintext = random(tc.PlainLen)

	er := stream.EncryptReader(bytes.NewReader(plaintext), nonce, associatedData)
	ciphertext, err = io.ReadAll(er)
	if err != nil {
		t.Fatalf("failed to encrypt plaintext: %v", err)
	}
	return stream, nonce, associatedData, plaintext, ciphertext
}

// TestBlockNumDecryptReader verifies that DecryptReader with blockNum = t
// decrypts the ciphertext suffix starting at block t into the plaintext
// suffix starting at t*bufSize.
func TestBlockNumDecryptReader(t *testing.T) {
	for i, tc := range blockNumTests {
		stream, nonce, ad, plaintext, ciphertext := newBlockNumCase(t, tc)

		blockSize := stream.bufSize + stream.cipher.Overhead()
		for cipherOff, blk := 0, 0; cipherOff < len(ciphertext); cipherOff, blk = cipherOff+blockSize, blk+1 {
			plainOff := blk * stream.bufSize

			dr := stream.DecryptReader(bytes.NewReader(ciphertext[cipherOff:]), nonce, ad)
			dr.Reset(uint32(blk))
			got, err := io.ReadAll(dr)
			if err != nil {
				t.Fatalf("Test %d: block %d: failed to decrypt: %v", i, blk, err)
			}
			if want := plaintext[plainOff:]; !bytes.Equal(got, want) {
				t.Fatalf("Test %d: block %d: plaintext mismatch: got %d bytes, want %d bytes", i, blk, len(got), len(want))
			}
		}
	}
}

// TestBlockNumEncryptReader verifies that EncryptReader with blockNum = t
// produces exactly the ciphertext suffix starting at block t, i.e. the same
// bytes a full encryption (blockNum = 0) would emit from block t onwards.
func TestBlockNumEncryptReader(t *testing.T) {
	for i, tc := range blockNumTests {
		stream, nonce, ad, plaintext, ciphertext := newBlockNumCase(t, tc)

		blockSize := stream.bufSize + stream.cipher.Overhead()
		for cipherOff, blk := 0, 0; cipherOff < len(ciphertext); cipherOff, blk = cipherOff+blockSize, blk+1 {
			plainOff := blk * stream.bufSize

			er := stream.EncryptReader(bytes.NewReader(plaintext[plainOff:]), nonce, ad)
			er.Reset(uint32(blk))
			got, err := io.ReadAll(er)
			if err != nil {
				t.Fatalf("Test %d: block %d: failed to encrypt: %v", i, blk, err)
			}
			if want := ciphertext[cipherOff:]; !bytes.Equal(got, want) {
				t.Fatalf("Test %d: block %d: ciphertext mismatch: got %d bytes, want %d bytes", i, blk, len(got), len(want))
			}
		}
	}
}

// TestBlockNumMatchesReaderAt cross-checks block-wise seeking via blockNum
// against the dedicated DecryptReaderAt seek API: decrypting the ciphertext
// suffix at block t with blockNum = t must yield the same plaintext as
// DecReaderAt.ReadAt at byte offset t*bufSize.
func TestBlockNumMatchesReaderAt(t *testing.T) {
	for i, tc := range blockNumTests {
		stream, nonce, ad, plaintext, ciphertext := newBlockNumCase(t, tc)
		readerAt := stream.DecryptReaderAt(bytes.NewReader(ciphertext), nonce, ad)

		blockSize := stream.bufSize + stream.cipher.Overhead()
		for cipherOff, blk := 0, 0; cipherOff < len(ciphertext); cipherOff, blk = cipherOff+blockSize, blk+1 {
			plainOff := blk * stream.bufSize
			want := plaintext[plainOff:]

			dr := stream.DecryptReader(bytes.NewReader(ciphertext[cipherOff:]), nonce, ad)
			dr.Reset(uint32(blk))
			viaBlockNum, err := io.ReadAll(dr)
			if err != nil {
				t.Fatalf("Test %d: block %d: blockNum decrypt failed: %v", i, blk, err)
			}

			viaReadAt := make([]byte, len(want))
			if _, err := readerAt.ReadAt(viaReadAt, int64(plainOff)); err != nil && err != io.EOF {
				t.Fatalf("Test %d: block %d: ReadAt failed: %v", i, blk, err)
			}

			if !bytes.Equal(viaBlockNum, want) || !bytes.Equal(viaReadAt, want) {
				t.Fatalf("Test %d: block %d: blockNum seek and ReadAt disagree", i, blk)
			}
		}
	}
}

// TestBlockNumWrongBlockNum verifies that decrypting a ciphertext suffix with
// the wrong blockNum (i.e. a sequence number that does not match the block's
// nonce) is rejected as not authentic, rather than silently returning
// garbage. This guards the integrity property of block-wise seeking.
func TestBlockNumWrongBlockNum(t *testing.T) {
	for i, tc := range blockNumTests {
		stream, nonce, ad, _, ciphertext := newBlockNumCase(t, tc)

		blockSize := stream.bufSize + stream.cipher.Overhead()
		if len(ciphertext) <= blockSize {
			continue // need at least a second block to mis-address
		}

		// Feed the second block (index 1, sealed with seqNum 2) but claim it
		// is the first block (blockNum 0 => seqNum 1).
		dr := stream.DecryptReader(bytes.NewReader(ciphertext[blockSize:]), nonce, ad)
		dr.Reset(0)
		if _, err := io.ReadAll(dr); err != NotAuthentic {
			t.Fatalf("Test %d: expected NotAuthentic for wrong blockNum, got %v", i, err)
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
