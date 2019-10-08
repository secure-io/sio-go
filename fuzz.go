// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build gofuzz

package sio

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
)

var stream *Stream

func init() {
	key := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	stream = NewStream(gcm, BufSize)
}

func Fuzz(data []byte) int {
	nonce := make([]byte, stream.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}

	plaintext := bytes.NewBuffer(make([]byte, 0, len(data)))
	var r io.Reader = stream.DecryptReader(stream.EncryptReader(bytes.NewReader(data), nonce, data), nonce, data)
	var w io.WriteCloser = stream.EncryptWriter(stream.DecryptWriter(plaintext, nonce, data), nonce, data)
	if _, err = io.Copy(w, r); err != nil {
		panic(err)
	}
	if err = w.Close(); err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext.Bytes(), data) {
		panic("en/decryption chain produces different plaintext")
	}

	plaintext.Reset()
	r = stream.DecryptReader(stream.EncryptReader(bytes.NewReader(data), nonce, data), nonce, data)
	w = stream.EncryptWriter(stream.DecryptWriter(plaintext, nonce, data), nonce, data)
	if _, err = copyBuffer(w, r, make([]byte, 2*BufSize+1)); err != nil {
		panic(err)
	}
	if err = w.Close(); err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext.Bytes(), data) {
		panic("en/decryption chain produces different plaintext")
	}

	plaintext.Reset()
	r = stream.EncryptReader(bytes.NewReader(data), nonce, data)
	w = stream.DecryptWriter(plaintext, nonce, data)
	if _, err = copyBuffer(w, r, make([]byte, 2*BufSize)); err != nil {
		panic(err)
	}
	if err = w.Close(); err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext.Bytes(), data) {
		panic("en/decryption chain produces different plaintext")
	}

	r = stream.DecryptReader(bytes.NewReader(data), nonce, data)
	if _, err = io.Copy(ioutil.Discard, r); err != NotAuthentic {
		panic(err)
	}
	w = stream.DecryptWriter(ioutil.Discard, nonce, data)
	if _, err = w.Write(data); err != NotAuthentic {
		if cErr := w.Close(); cErr != NotAuthentic || err != nil {
			panic(fmt.Sprintf("Write error: %v - Close error: %v", err, cErr))
		}
	}
	return 0
}

func copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	var written int64
	var err error
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}
