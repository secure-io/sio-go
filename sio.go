// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package sio implements a provable secure authenticated encryption
// scheme for continuous byte streams.
package sio

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"
)

const (
	// MaxBufSize is the maximum buffer size for streams.
	MaxBufSize = (1 << 24) - 1

	// BufSize is the recommended buffer size for streams.
	BufSize = 1 << 14
)

var (
	// ErrAuth is returned when the decryption of a data stream fails.
	// It indicates that the data is not authentic (e.g. malisously
	// modified).
	ErrAuth = errAuth{}

	// ErrExceeded is returned when no more data can be encrypted /
	// decrypted securely. It indicates that the data stream is too
	// large to be encrypted / decrypted with a single key-nonce
	// combination.
	ErrExceeded = errExceeded{}
)

// The following error type construction prevents assigning new values to
// ErrAuth or ErrExceeded. In particular it prevents client code from doing
// shady things like:
//
//   `sio.ErrAuth = nil` or `sio.ErrAuth = sio.ErrExceeded`
//
// In contrast you could write e.g. `io.EOF = nil` which will most likely break
// any I/O code in horrible ways.

type errType struct{ _ int }

type errAuth errType

func (errAuth) Error() string { return "sio: authentication failed" }

type errExceeded errType

func (errExceeded) Error() string { return "sio: data limit exceeded" }

// NewStream creates a new Stream that encrypts or decrypts data
// streams with the cipher. If you don't have special requirements
// just use the default BufSize.
//
// The returned Stream will allocate a new bufSize large buffer
// when en/decrypting a data stream.
//
// The cipher must support a NonceSize() >= 4 and the
// bufSize must be between 1 (inclusive) and MaxBufSize (inclusive).
func NewStream(cipher cipher.AEAD, bufSize int) *Stream {
	if cipher.NonceSize() < 4 {
		panic("sio: NonceSize() of cipher is too small")
	}
	if bufSize > MaxBufSize {
		panic("sio: bufSize is too large")
	}
	if bufSize <= 0 {
		panic("sio: bufSize is too small")
	}
	return &Stream{
		cipher:  cipher,
		bufSize: bufSize,
	}
}

// A Stream encrypts or decrypts continuous byte streams.
type Stream struct {
	cipher  cipher.AEAD
	bufSize int
}

// NonceSize returns the size of the unique nonce that must be
// provided when encrypting or decrypting a data stream.
func (s *Stream) NonceSize() int { return s.cipher.NonceSize() - 4 }

// Overhead returns the overhead added when encrypting a
// data stream. It panic's if the length is either negative
// or exceeds the data limit of (2³² - 1) * bufSize bytes.
func (s *Stream) Overhead(length int64) int64 {
	if length < 0 {
		panic("sio: length is negative")
	}
	if length > int64(s.bufSize)*((1<<32)-1) {
		panic("sio: length exceeds data limit")
	}

	overhead := int64(s.cipher.Overhead())
	if length == 0 {
		return overhead
	}

	t := length / int64(s.bufSize)
	if r := length % int64(s.bufSize); r > 0 {
		return (t * overhead) + overhead
	}
	return t * overhead
}

// EncryptWriter returns a new EncWriter that wraps w and
// encrypts and authenticates everything written to it.
// The nonce must be NonceSize() bytes long and unique for
// the same key (used to create cipher.AEAD). The
// associatedData is authenticated but neither encrypted nor
// written to w and must be provided whenever decrypting the
// data again.
func (s *Stream) EncryptWriter(w io.Writer, nonce, associatedData []byte) *EncWriter {
	if len(nonce) != s.NonceSize() {
		panic("sio: nonce has invalid length")
	}
	ew := &EncWriter{
		w:              w,
		cipher:         s.cipher,
		bufSize:        s.bufSize,
		nonce:          make([]byte, s.cipher.NonceSize()),
		associatedData: make([]byte, 1+s.cipher.Overhead()),
		buffer:         make([]byte, s.bufSize+s.cipher.Overhead()),
	}
	copy(ew.nonce, nonce)
	nextNonce, _ := ew.nextNonce()
	ew.associatedData[0] = 0x00
	ew.cipher.Seal(ew.associatedData[1:1], nextNonce, nil, associatedData)
	return ew
}

// DecryptWriter returns a new DecWriter that wraps w and
// decrypts and verifies everything written to it. The
// nonce and associatedData must match the values used
// when encrypting the data. The associatedData is not
// written to w.
func (s *Stream) DecryptWriter(w io.Writer, nonce, associatedData []byte) *DecWriter {
	if len(nonce) != s.NonceSize() {
		panic("sio: nonce has invalid length")
	}
	dw := &DecWriter{
		w:              w,
		cipher:         s.cipher,
		bufSize:        s.bufSize,
		nonce:          make([]byte, s.cipher.NonceSize()),
		associatedData: make([]byte, 1+s.cipher.Overhead()),
		buffer:         make([]byte, s.bufSize+s.cipher.Overhead(), 1+s.bufSize+s.cipher.Overhead()),
	}
	copy(dw.nonce, nonce)
	nextNonce, _ := dw.nextNonce()
	dw.associatedData[0] = 0x00
	dw.cipher.Seal(dw.associatedData[1:1], nextNonce, nil, associatedData)
	return dw
}

// EncryptReader returns a new EncReader that wraps r and
// encrypts and authenticates everything it reads. The
// nonce must be NonceSize() bytes long and unique for
// the same key (used to create cipher.AEAD). The
// associatedData is authenticated but not encrypted.
func (s *Stream) EncryptReader(r io.Reader, nonce, associatedData []byte) *EncReader {
	if len(nonce) != s.NonceSize() {
		panic("sio: nonce has invalid length")
	}
	er := &EncReader{
		r:              r,
		cipher:         s.cipher,
		bufSize:        s.bufSize,
		nonce:          make([]byte, s.cipher.NonceSize()),
		associatedData: make([]byte, 1+s.cipher.Overhead()),
		buffer:         make([]byte, 1+s.bufSize+s.cipher.Overhead()),
		firstRead:      true,
	}
	copy(er.nonce, nonce)
	er.associatedData[0] = 0x00
	binary.LittleEndian.PutUint32(er.nonce[er.cipher.NonceSize()-4:], er.seqNum)
	er.cipher.Seal(er.associatedData[1:1], er.nonce, nil, associatedData)
	er.seqNum = 1
	return er
}

// DecryptReader returns a new DecReader that wraps r and
// decrypts and verifies everything it reads. The nonce
// and associatedData must match the values used to
// encrypt the data.
func (s *Stream) DecryptReader(r io.Reader, nonce, associatedData []byte) *DecReader {
	if len(nonce) != s.NonceSize() {
		panic("sio: nonce has invalid length")
	}
	dr := &DecReader{
		r:              r,
		cipher:         s.cipher,
		bufSize:        s.bufSize,
		nonce:          make([]byte, s.cipher.NonceSize()),
		associatedData: make([]byte, 1+s.cipher.Overhead()),
		buffer:         make([]byte, 1+s.bufSize+s.cipher.Overhead()),
		firstRead:      true,
	}
	copy(dr.nonce, nonce)
	dr.associatedData[0] = 0x00
	binary.LittleEndian.PutUint32(dr.nonce[dr.cipher.NonceSize()-4:], dr.seqNum)
	dr.cipher.Seal(dr.associatedData[1:1], dr.nonce, nil, associatedData)
	dr.seqNum = 1
	return dr
}

// DecryptReaderAt returns a new DecReaderAt that wraps r and
// decrypts and verifies everything it reads. The nonce
// and associatedData must match the values used to
// encrypt the data.
func (s *Stream) DecryptReaderAt(r io.ReaderAt, nonce, associatedData []byte) *DecReaderAt {
	if len(nonce) != s.NonceSize() {
		panic("sio: nonce has invalid length")
	}
	dr := &DecReaderAt{
		r:              r,
		cipher:         s.cipher,
		bufSize:        s.bufSize,
		nonce:          make([]byte, s.cipher.NonceSize()),
		associatedData: make([]byte, 1+s.cipher.Overhead()),
	}
	copy(dr.nonce, nonce)
	dr.associatedData[0] = 0x00
	binary.LittleEndian.PutUint32(dr.nonce[s.NonceSize():], 0)
	dr.cipher.Seal(dr.associatedData[1:1], dr.nonce, nil, associatedData)

	dr.bufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 1+dr.bufSize+dr.cipher.Overhead())
			return &b
		},
	}
	return dr
}

// writeTo writes p to w. It returns the first error that occurs during
// writing, if any. If w violates the io.Writer contract and returns less than
// len(p) bytes but no error then writeTo returns io.ErrShortWrite.
func writeTo(w io.Writer, p []byte) (int, error) {
	n, err := w.Write(p)
	if err != nil {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// readFrom reads len(p) bytes from r into p. It returns the first error that
// occurs during reading, if any. If the returned n < len(p) than the returned
// error is not nil.
func readFrom(r io.Reader, p []byte) (n int, err error) {
	for n < len(p) && err == nil {
		var nn int
		nn, err = r.Read(p[n:])
		n += nn
	}
	if err == io.EOF && n == len(p) {
		err = nil
	}
	return n, err
}
