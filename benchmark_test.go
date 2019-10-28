// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkEncrypt(b *testing.B) {
	s, err := AES_128_GCM.Stream(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Stream: %v", err)
	}

	b.Run("Write", func(b *testing.B) {
		b.Run("1K", func(b *testing.B) { benchEncryptWrite(b, s, 1024) })
		b.Run("64K", func(b *testing.B) { benchEncryptWrite(b, s, 64*1024) })
		b.Run("512K", func(b *testing.B) { benchEncryptWrite(b, s, 512*1024) })
		b.Run("1M", func(b *testing.B) { benchEncryptWrite(b, s, 1024*1024) })
	})
	b.Run("WriteTo", func(b *testing.B) {
		b.Run("1K", func(b *testing.B) { benchEncryptWriteTo(b, s, 1024) })
		b.Run("64K", func(b *testing.B) { benchEncryptWriteTo(b, s, 64*1024) })
		b.Run("512K", func(b *testing.B) { benchEncryptWriteTo(b, s, 512*1024) })
		b.Run("1M", func(b *testing.B) { benchEncryptWriteTo(b, s, 1024*1024) })
	})
	b.Run("Read", func(b *testing.B) {
		b.Run("1K", func(b *testing.B) { benchEncryptRead(b, s, 1024) })
		b.Run("64K", func(b *testing.B) { benchEncryptRead(b, s, 64*1024) })
		b.Run("512K", func(b *testing.B) { benchEncryptRead(b, s, 512*1024) })
		b.Run("1M", func(b *testing.B) { benchEncryptRead(b, s, 1024*1024) })
	})
	b.Run("ReadFrom", func(b *testing.B) {
		b.Run("1K", func(b *testing.B) { benchEncryptReadFrom(b, s, 1024) })
		b.Run("64K", func(b *testing.B) { benchEncryptReadFrom(b, s, 64*1024) })
		b.Run("512K", func(b *testing.B) { benchEncryptReadFrom(b, s, 512*1024) })
		b.Run("1M", func(b *testing.B) { benchEncryptReadFrom(b, s, 1024*1024) })
	})
}

func BenchmarkDecrypt(b *testing.B) {
	s, err := AES_128_GCM.Stream(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Stream: %v", err)
	}

	b.Run("Write", func(b *testing.B) {
		b.Run("1K", func(b *testing.B) { benchDecryptWrite(b, s, 1024) })
		b.Run("64K", func(b *testing.B) { benchDecryptWrite(b, s, 64*1024) })
		b.Run("512K", func(b *testing.B) { benchDecryptWrite(b, s, 512*1024) })
		b.Run("1M", func(b *testing.B) { benchDecryptWrite(b, s, 1024*1024) })
	})
	b.Run("WriteTo", func(b *testing.B) {
		b.Run("1K", func(b *testing.B) { benchDecryptWriteTo(b, s, 1024) })
		b.Run("64K", func(b *testing.B) { benchDecryptWriteTo(b, s, 64*1024) })
		b.Run("512K", func(b *testing.B) { benchDecryptWriteTo(b, s, 512*1024) })
		b.Run("1M", func(b *testing.B) { benchDecryptWriteTo(b, s, 1024*1024) })
	})
	b.Run("Read", func(b *testing.B) {
		b.Run("1K", func(b *testing.B) { benchDecryptRead(b, s, 1024) })
		b.Run("64K", func(b *testing.B) { benchDecryptRead(b, s, 64*1024) })
		b.Run("512K", func(b *testing.B) { benchDecryptRead(b, s, 512*1024) })
		b.Run("1M", func(b *testing.B) { benchDecryptRead(b, s, 1024*1024) })
	})
	b.Run("ReadFrom", func(b *testing.B) {
		b.Run("1K", func(b *testing.B) { benchDecryptReadFrom(b, s, 1024) })
		b.Run("64K", func(b *testing.B) { benchDecryptReadFrom(b, s, 64*1024) })
		b.Run("512K", func(b *testing.B) { benchDecryptReadFrom(b, s, 512*1024) })
		b.Run("1M", func(b *testing.B) { benchDecryptReadFrom(b, s, 1024*1024) })
	})
	b.Run("ReadAt", func(b *testing.B) {
		b.Run("1K", func(b *testing.B) { benchDecryptReadAt(b, s, 0, 1024) })
		b.Run("64K", func(b *testing.B) { benchDecryptReadAt(b, s, 0, 64*1024) })
		b.Run("512K", func(b *testing.B) { benchDecryptReadAt(b, s, 0, 512*1024) })
		b.Run("1M", func(b *testing.B) { benchDecryptReadAt(b, s, 0, 1024*1024) })

		b.Run("512_1K", func(b *testing.B) { benchDecryptReadAt(b, s, 512, 1024) })
		b.Run("1K_64K", func(b *testing.B) { benchDecryptReadAt(b, s, 1024, 64*1024) })
		b.Run("65K_512K", func(b *testing.B) { benchDecryptReadAt(b, s, 65*1024, 512*1024) })
		b.Run("129K_1M", func(b *testing.B) { benchDecryptReadAt(b, s, 129*1024, 1024*1024) })
	})
}

func benchEncryptWrite(b *testing.B, s *Stream, size int64) {
	w := s.EncryptWriter(DevNull, make([]byte, s.NonceSize()), nil)
	plaintext := make([]byte, size)
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Write(plaintext)
		w.Close()

		w.seqNum = 1
		w.offset = 0
		w.closed = false
		w.associatedData[0] = 0
	}
}

func benchDecryptWrite(b *testing.B, s *Stream, size int64) {
	plaintext := make([]byte, size)
	nonce := make([]byte, s.NonceSize())
	ow := s.DecryptWriter(DevNull, nonce, nil)
	w := s.EncryptWriter(ow, nonce, nil)
	b.SetBytes(2*size + s.Overhead(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Write(plaintext)
		w.Close()

		w.seqNum, ow.seqNum = 1, 1
		w.offset, ow.offset = 0, 0
		w.closed, ow.closed = false, false
		w.associatedData[0], ow.associatedData[0] = 0, 0
	}
}

func benchEncryptReadFrom(b *testing.B, s *Stream, size int64) {
	plaintext := &io.LimitedReader{R: DevNull, N: size}
	w := s.EncryptWriter(DevNull, make([]byte, s.NonceSize()), nil)
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.ReadFrom(plaintext); err != nil {
			panic(err)
		}

		w.seqNum = 1
		w.offset = 0
		w.closed = false
		w.associatedData[0] = 0
		plaintext.N = size
	}
}

func benchDecryptReadFrom(b *testing.B, s *Stream, size int64) {
	plaintext := &io.LimitedReader{R: DevNull, N: size}
	nonce := make([]byte, s.NonceSize())
	ow := s.DecryptWriter(DevNull, nonce, nil)
	w := s.EncryptWriter(ow, nonce, nil)
	b.SetBytes(2*size + s.Overhead(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.ReadFrom(plaintext); err != nil {
			panic(err)
		}

		w.seqNum, ow.seqNum = 1, 1
		w.offset, ow.offset = 0, 0
		w.closed, ow.closed = false, false
		w.associatedData[0], ow.associatedData[0] = 0, 0
		plaintext.N = size
	}
}

func benchEncryptRead(b *testing.B, s *Stream, size int64) {
	nonce := make([]byte, s.NonceSize())
	buffer := make([]byte, s.bufSize+s.cipher.Overhead())
	plaintext := &io.LimitedReader{R: DevNull, N: size}

	r := s.EncryptReader(plaintext, nonce, nil)
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for {
			if _, err := readFrom(r, buffer); err == io.EOF {
				break
			} else if err != nil {
				panic(err)
			}
		}

		r.seqNum = 1
		r.offset = 0
		r.closed = false
		r.firstRead = true
		r.associatedData[0] = 0
		plaintext.N = size
	}
}

func benchDecryptRead(b *testing.B, s *Stream, size int64) {
	nonce := make([]byte, s.NonceSize())
	buffer := make([]byte, s.bufSize)
	plaintext := &io.LimitedReader{R: DevNull, N: size}

	sr := s.EncryptReader(plaintext, nonce, nil)
	r := s.DecryptReader(sr, nonce, nil)
	b.SetBytes(2*size + s.Overhead(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for {
			if _, err := readFrom(r, buffer); err == io.EOF {
				break
			} else if err != nil {
				panic(err)
			}
		}

		r.seqNum, sr.seqNum = 1, 1
		r.offset, sr.offset = 0, 0
		r.closed, sr.closed = false, false
		r.firstRead, sr.firstRead = true, true
		r.associatedData[0], sr.associatedData[0] = 0, 0
		plaintext.N = size
	}
}

func benchDecryptReadAt(b *testing.B, s *Stream, offset, size int64) {
	nonce := make([]byte, s.NonceSize())

	data := make([]byte, size)
	ciphertext := bytes.NewBuffer(nil)
	w := s.EncryptWriter(ciphertext, nonce, nil)
	w.Write(data)
	w.Close()

	r := s.DecryptReaderAt(bytes.NewReader(ciphertext.Bytes()), nonce, nil)
	b.SetBytes(size - offset + s.Overhead(size-offset))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.ReadAt(data, offset); err != nil {
			if err != io.EOF {
				panic(err)
			}
		}
	}
}

func benchEncryptWriteTo(b *testing.B, s *Stream, size int64) {
	nonce := make([]byte, s.NonceSize())
	plaintext := &io.LimitedReader{R: DevNull, N: size}

	r := s.EncryptReader(plaintext, nonce, nil)
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.WriteTo(DevNull); err != nil {
			panic(err)
		}

		r.seqNum = 1
		r.offset = 0
		r.closed = false
		r.firstRead = true
		r.associatedData[0] = 0
		plaintext.N = size
	}
}

func benchDecryptWriteTo(b *testing.B, s *Stream, size int64) {
	nonce := make([]byte, s.NonceSize())
	plaintext := &io.LimitedReader{R: DevNull, N: size}

	sr := s.EncryptReader(plaintext, nonce, nil)
	r := s.DecryptReader(sr, nonce, nil)
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.WriteTo(DevNull); err != nil {
			panic(err)
		}

		r.seqNum, sr.seqNum = 1, 1
		r.offset, sr.offset = 0, 0
		r.closed, sr.closed = false, false
		r.firstRead, sr.firstRead = true, true
		r.associatedData[0], sr.associatedData[0] = 0, 0
		plaintext.N = size
	}
}
