// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/secure-io/sio-go"
	"golang.org/x/crypto/chacha20poly1305"
)

func ExampleNewStream_aESGCM() {
	// Load your secret key from a safe place. You should use a unique key
	// per data stream since the nonce size of `Stream` (with AES-GCM) is
	// to short for chosing a nonce at random (risk of repeating the
	// nonce is too high).
	// Obviously don't use this example key for anything real.
	// If you want to convert a passphrase to a key, use a suitable
	// package like argon2 or scrypt. Use 16 byte (128 bit) for
	// AES128-GCM and 32 byte (256 bit) for AES256-GCM.
	key, _ := hex.DecodeString("4310889c63c87a957e11e0b3d75047beadc8736d72fc1407439862e85a7377f4")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	stream := sio.NewStream(gcm, sio.BufSize)

	// Print the nonce size for Stream (with AES-GCM) and the overhead added
	// when encrypting a 1 MiB data stream.
	fmt.Printf("NonceSize: %d, Overhead: %d", stream.NonceSize(), stream.Overhead(1024*1024))
	//Output: NonceSize: 8, Overhead: 1024
}

func ExampleNewStream_xChaCha20Poly1305() {
	// Load your secret key from a safe place. You may reuse it for
	// en/decrypting multiple data streams. (XChaCha20-Poly1305 nonce
	// values are large enough to be chosen at random without risking
	// to select a nonce twice - probability is negligible).
	//
	// Obviously don't use this example key for anything real.
	// If you want to convert a passphrase to a key, use a suitable
	// package like argon2 or scrypt - or take a look at the sio/sioutil
	// package.
	key, _ := hex.DecodeString("f230e700c4f120b623b84ac26cbcb5ae926f44f36589e63745a46ae0ca47137d")
	x20p1305, _ := chacha20poly1305.NewX(key)

	stream := sio.NewStream(x20p1305, sio.BufSize)

	// Print the nonce size for Stream (with XChaCha20-Poly1305) and the
	// overhead added when encrypting a 1 MiB data stream.
	fmt.Printf("NonceSize: %d, Overhead: %d", stream.NonceSize(), stream.Overhead(1024*1024))
	//Output: NonceSize: 20, Overhead: 1024
}

func ExampleEncReader() {
	// Use an unique key per data stream. For example derive one
	// from a password using a suitable package like argon2 or
	// from a master key using e.g. HKDF.
	// Obviously don't use this example key for anything real.
	key, _ := hex.DecodeString("ffb0823fcab82a983e1725e003c702252ef4fc7054796b3c23d08aa189f662c9")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	stream := sio.NewStream(gcm, sio.BufSize)

	var (
		// Use a unique nonce per key. If you choose an unique key
		// you can also set the nonce to all zeros. (What to prefer
		// depends on the application).
		nonce []byte = make([]byte, stream.NonceSize())

		// If you want to bind additional data to the ciphertext
		// (e.g. a file name to prevent renaming / moving the file)
		// set the associated data. But be aware that the associated
		// data is not encrypted (only authenticated) and must be
		// available when decrypting the ciphertext again.
		associatedData []byte = nil
	)

	plaintext := strings.NewReader("some plaintext")
	r := stream.EncryptReader(plaintext, nonce, associatedData)

	// Reading from r returns encrypted and authenticated data.
	ioutil.ReadAll(r)
	//Output:
}

func ExampleDecReader() {
	// Use the key used to encrypt the data. (See e.g. the EncReader example).
	// Obviously don't use this example key for anything real.
	key, _ := hex.DecodeString("ffb0823fcab82a983e1725e003c702252ef4fc7054796b3c23d08aa189f662c9")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	stream := sio.NewStream(gcm, sio.BufSize)

	var (
		// Use the nonce value using during encryption.
		// (See e.g. the EncWriter example).
		nonce []byte = make([]byte, stream.NonceSize())

		// Use the associated data using during encryption.
		// (See e.g. the EncWriter example).
		associatedData []byte = nil
	)

	ciphertext := hex.NewDecoder(strings.NewReader("9f54ed8df9cffaff02eddb479b95fd3bed9391758a4f81376cfadd7f8c00"))
	r := stream.DecryptReader(ciphertext, nonce, associatedData)

	// Reading from r returns the original plaintext (or an error).
	if _, err := ioutil.ReadAll(r); err != nil {
		if err == sio.NotAuthentic {
			// Read data is not authentic -> ciphertext has been modified.
			// TODO: error handling
			panic(err)
		}
	}
	//Output:
}

func ExampleDecReaderAt() {
	// Use the key used to encrypt the data. (See e.g. the EncReader example).
	// Obviously don't use this example key for anything real.
	key, _ := hex.DecodeString("ffb0823fcab82a983e1725e003c702252ef4fc7054796b3c23d08aa189f662c9")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	stream := sio.NewStream(gcm, sio.BufSize)

	var (
		// Use the nonce value using during encryption.
		// (See e.g. the EncWriter example).
		nonce []byte = make([]byte, stream.NonceSize())

		// Use the associated data using during encryption.
		// (See e.g. the EncWriter example).
		associatedData []byte = nil
	)

	rawBytes, _ := hex.DecodeString("9f54ed8df9cffaff02eddb479b95fd3bed9391758a4f81376cfadd7f8c00")
	ciphertext := bytes.NewReader(rawBytes)
	r := stream.DecryptReaderAt(ciphertext, nonce, associatedData)
	section := io.NewSectionReader(r, 5, 9) // Read the 'plaintext' substring from 'some plaintext'

	// Reading from section returns the original plaintext (or an error).
	if _, err := ioutil.ReadAll(section); err != nil {
		if err == sio.NotAuthentic {
			// Read data is not authentic -> ciphertext has been modified.
			// TODO: error handling
			panic(err)
		}
	}
	//Output:
}

func ExampleEncWriter() {
	// Use an unique key per data stream. For example derive one
	// from a password using a suitable package like argon2 or
	// from a master key using e.g. HKDF.
	// Obviously don't use this example key for anything real.
	key, _ := hex.DecodeString("ffb0823fcab82a983e1725e003c702252ef4fc7054796b3c23d08aa189f662c9")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	stream := sio.NewStream(gcm, sio.BufSize)

	var (
		// Use a unique nonce per key. If you choose an unique key
		// you can also set the nonce to all zeros. (What to prefer
		// depends on the application).
		nonce []byte = make([]byte, stream.NonceSize())

		// If you want to bind additional data to the ciphertext
		// (e.g. a file name to prevent renaming / moving the file)
		// set the associated data. But be aware that the associated
		// data is not encrypted (only authenticated) and must be
		// available when decrypting the ciphertext again.
		associatedData []byte = nil
	)

	ciphertext := bytes.NewBuffer(nil) // You can also use the plaintext size and stream.Overhead() to avoid re-allocation.
	w := stream.EncryptWriter(ciphertext, nonce, associatedData)
	defer func() {
		if err := w.Close(); err != nil { // The EncWriter must be closed to complete the encryption.
			panic(err) // TODO: error handling
		}
	}()

	// Writing plaintext to w writes encrypted and authenticated data to
	// the underlying io.Writer (i.e. the ciphertext *bytes.Buffer)
	if _, err := io.WriteString(w, "some plaintext"); err != nil {
		// TODO: error handling
	}
	//Output:
}

func ExampleDecWriter() {
	// Use the key used to encrypt the data. (See e.g. the EncWriter example).
	// Obviously don't use this example key for anything real.
	key, _ := hex.DecodeString("ffb0823fcab82a983e1725e003c702252ef4fc7054796b3c23d08aa189f662c9")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	stream := sio.NewStream(gcm, sio.BufSize)

	var (
		// Use the nonce value using during encryption.
		// (See e.g. the EncWriter example).
		nonce []byte = make([]byte, stream.NonceSize())

		// Use the associated data using during encryption.
		// (See e.g. the EncWriter example).
		associatedData []byte = nil
	)

	plaintext := bytes.NewBuffer(nil)
	w := stream.DecryptWriter(plaintext, nonce, associatedData)
	defer func() {
		if err := w.Close(); err != nil {
			if err == sio.NotAuthentic { // During Close() the DecWriter may detect unauthentic data -> decryption error.
				panic(err) // TODO: error handling
			}
			panic(err) // TODO: error handling
		}
	}()

	ciphertext, _ := hex.DecodeString("9f54ed8df9cffaff02eddb479b95fd3bed9391758a4f81376cfadd7f8c00")

	// Writing ciphertext to w writes decrypted and verified data to
	// the underlying io.Writer (i.e. the plaintext *bytes.Buffer) or
	// returns an error.
	if _, err := w.Write(ciphertext); err != nil {
		if err == sio.NotAuthentic {
			// Read data is not authentic -> ciphertext has been modified.
			// TODO: error handling
			panic(err)
		}
	}
	//Output:
}
