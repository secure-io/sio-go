// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	mrand "math/rand"
)

var DevNull = devNull{}

type devNull struct{}

func (devNull) Read(p []byte) (int, error)  { return len(p), nil }
func (devNull) Write(p []byte) (int, error) { return len(p), nil }

func random(size int) []byte {
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	return key
}

func randomN(size int) []byte {
	key := make([]byte, mrand.Intn(size))
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	return key
}

func copyBytes(dst io.ByteWriter, src io.ByteReader) error {
	for {
		b, err := src.ReadByte()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err = dst.WriteByte(b); err != nil {
			return err
		}
	}
}

func loadTestVectors(filename string) []TestVector {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	var vec []struct {
		Algorithm      algorithm
		BufSize        int
		Key            string
		Nonce          string
		AssociatedData string
		Plaintext      string
		Ciphertext     string
	}
	if err = json.Unmarshal(data, &vec); err != nil {
		panic(err)
	}

	testVectors := make([]TestVector, len(vec))
	for i, v := range vec {
		key, err := hex.DecodeString(v.Key)
		if err != nil {
			panic(err)
		}
		nonce, err := hex.DecodeString(v.Nonce)
		if err != nil {
			panic(err)
		}
		associatedData, err := hex.DecodeString(v.AssociatedData)
		if err != nil {
			panic(err)
		}
		plaintext, err := hex.DecodeString(v.Plaintext)
		if err != nil {
			panic(err)
		}
		ciphertext, err := hex.DecodeString(v.Ciphertext)
		if err != nil {
			panic(err)
		}
		testVectors[i] = TestVector{
			Algorithm:      v.Algorithm,
			BufSize:        v.BufSize,
			Key:            key,
			Nonce:          nonce,
			AssociatedData: associatedData,
			Plaintext:      plaintext,
			Ciphertext:     ciphertext,
		}
	}
	return testVectors
}
