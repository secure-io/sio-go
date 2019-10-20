// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio

import (
	mrand "math/rand"
)

type TestVector struct {
	Algorithm      algorithm
	BufSize        int
	Key            []byte
	Nonce          []byte
	AssociatedData []byte
	Plaintext      []byte
	Ciphertext     []byte
}

var TestVectors []TestVector = loadTestVectors("./test_vectors.json")

type SimpleTest struct {
	Algorithm      algorithm
	BufSize        int
	Key            []byte
	Nonce          []byte
	AssociatedData []byte
	Plaintext      []byte
}

var SimpleTests = []SimpleTest{
	SimpleTest{ // 0
		Algorithm:      AES_128_GCM,
		BufSize:        BufSize,
		Key:            make([]byte, 128/8),
		Nonce:          make([]byte, 64/8),
		AssociatedData: nil,
		Plaintext:      randomN(1 << 20),
	},
	SimpleTest{ // 1
		Algorithm:      AES_128_GCM,
		BufSize:        1 + mrand.Intn(2*BufSize), // add 1 to ensure BufSize is not 0.
		Key:            random(128 / 8),
		Nonce:          random(64 / 8),
		AssociatedData: randomN(256),
		Plaintext:      randomN(1 << 20),
	},
	SimpleTest{ // 2
		Algorithm:      AES_128_GCM,
		BufSize:        BufSize,
		Key:            random(128 / 8),
		Nonce:          random(64 / 8),
		AssociatedData: randomN(256),
		Plaintext:      nil,
	},
	SimpleTest{ // 3
		Algorithm:      AES_128_GCM,
		BufSize:        BufSize,
		Key:            random(128 / 8),
		Nonce:          random(64 / 8),
		AssociatedData: randomN(256),
		Plaintext:      random(1),
	},
	SimpleTest{ // 4
		Algorithm:      AES_128_GCM,
		BufSize:        BufSize,
		Key:            random(128 / 8),
		Nonce:          random(64 / 8),
		AssociatedData: randomN(256),
		Plaintext:      random(BufSize - 1),
	},
	SimpleTest{ // 5
		Algorithm:      AES_128_GCM,
		BufSize:        BufSize,
		Key:            random(128 / 8),
		Nonce:          random(64 / 8),
		AssociatedData: randomN(256),
		Plaintext:      random(BufSize),
	},
	SimpleTest{ // 6
		Algorithm:      AES_128_GCM,
		BufSize:        BufSize,
		Key:            random(128 / 8),
		Nonce:          random(64 / 8),
		AssociatedData: randomN(256),
		Plaintext:      random(BufSize + 1),
	},
	SimpleTest{ // 7
		Algorithm:      AES_128_GCM,
		BufSize:        1,
		Key:            random(128 / 8),
		Nonce:          random(64 / 8),
		AssociatedData: randomN(256),
		Plaintext:      []byte{},
	},
	SimpleTest{ // 8
		Algorithm:      AES_128_GCM,
		BufSize:        1,
		Key:            random(128 / 8),
		Nonce:          random(64 / 8),
		AssociatedData: randomN(256),
		Plaintext:      randomN(1 << 20),
	},
	SimpleTest{ // 9
		Algorithm:      AES_128_GCM,
		BufSize:        2*BufSize + 1,
		Key:            random(128 / 8),
		Nonce:          random(64 / 8),
		AssociatedData: randomN(1 << 20),
		Plaintext:      randomN(1 << 20),
	},
}
