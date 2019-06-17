// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"sync"
)

// EncReader wraps is an io.Reader and encrypts and authenticates everything it
// reads from it.
type EncReader struct {
	r       io.Reader
	cipher  cipher.AEAD
	bufSize int

	seqNum         uint32
	nonce          []byte
	associatedData []byte

	buffer           []byte
	ciphertextBuffer []byte
	offset           int

	err               error
	carry             byte
	firstRead, closed bool
}

// Read behaves like specified by the io.Reader interface.
// It encryptes and authenticates up to len(p) bytes which it
// reads from the underlying io.Reader.
//
// It returns ErrExceeded when no more data can be encrypted
// securely.
func (r *EncReader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return n, r.err
	}
	if r.firstRead {
		r.firstRead = false
		n, err = r.readFragment(p, 0)
		if err != nil {
			return n, err
		}
		p = p[n:]
	}
	if r.offset > 0 {
		nn := copy(p, r.ciphertextBuffer[r.offset:])
		n += nn
		if nn == len(p) {
			r.offset += nn
			return n, nil
		}
		p = p[nn:]
		r.offset = 0
	}
	if r.closed {
		return n, io.EOF
	}
	nn, err := r.readFragment(p, 1)
	return n + nn, err
}

// ReadByte reads from the underlying io.Reader and
// returns one encrypted and authenticated byte.
//
// It returns ErrExceeded when no more bytes can
// be encrypted securely.
func (r *EncReader) ReadByte() (byte, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.firstRead {
		r.firstRead = false
		if _, err := r.readFragment(nil, 0); err != nil {
			return 0, err
		}
		b := r.ciphertextBuffer[0]
		r.offset = 1
		return b, nil
	}

	if r.offset > 0 && r.offset < len(r.ciphertextBuffer) {
		b := r.ciphertextBuffer[r.offset]
		r.offset++
		return b, nil
	}
	if r.closed {
		return 0, io.EOF
	}

	r.offset = 0
	if _, err := r.readFragment(nil, 1); err != nil {
		return 0, err
	}
	b := r.ciphertextBuffer[0]
	r.offset = 1
	return b, nil
}

// WriteTo keeps reading from the underlying io.Reader
// until it enounters an error or io.EOF and encrypts
// and authenticates everything before writting it to w.
//
// It returns ErrExceeded when no more data can be encrypted
// securely.
func (r *EncReader) WriteTo(w io.Writer) (int64, error) {
	var n int64
	if r.firstRead {
		r.firstRead = false
		nn, err := r.readFragment(r.buffer, 0)
		if err != nil && err != io.EOF {
			return n, err
		}
		nn, err = writeTo(w, r.buffer[:nn])
		if err != nil {
			return n, err
		}
		n += int64(nn)
		if r.closed {
			return n, nil
		}
	}
	if r.err != nil {
		return n, r.err
	}
	if r.offset > 0 {
		nn, err := writeTo(w, r.ciphertextBuffer[r.offset:])
		if err != nil {
			r.err = err
			return n, err
		}
		r.offset = 0
		n += int64(nn)
	}
	if r.closed {
		return n, io.EOF
	}
	for {
		nn, err := r.readFragment(r.buffer, 1)
		if err != nil && err != io.EOF {
			return n, err
		}
		nn, err = writeTo(w, r.buffer[:nn])
		if err != nil {
			r.err = err
			return n, err
		}
		n += int64(nn)
		if r.closed {
			return n, nil
		}
	}
}

func (r *EncReader) readFragment(p []byte, firstReadOffset int) (int, error) {
	if r.seqNum == 0 {
		r.err = ErrExceeded
		return 0, r.err
	}
	binary.LittleEndian.PutUint32(r.nonce[r.cipher.NonceSize()-4:], r.seqNum)
	r.seqNum++

	r.buffer[0] = r.carry
	n, err := readFrom(r.r, r.buffer[firstReadOffset:1+r.bufSize])
	switch {
	default:
		r.carry = r.buffer[r.bufSize]
		if len(p) < r.bufSize+r.cipher.Overhead() {
			r.ciphertextBuffer = r.cipher.Seal(r.buffer[:0], r.nonce, r.buffer[:r.bufSize], r.associatedData)
			r.offset = copy(p, r.ciphertextBuffer)
			return r.offset, nil
		}
		r.cipher.Seal(p[:0], r.nonce, r.buffer[:r.bufSize], r.associatedData)
		return r.bufSize + r.cipher.Overhead(), nil
	case err == io.EOF:
		r.closed = true
		r.associatedData[0] = 0x80
		if len(p) < firstReadOffset+n+r.cipher.Overhead() {
			r.ciphertextBuffer = r.cipher.Seal(r.buffer[:0], r.nonce, r.buffer[:firstReadOffset+n], r.associatedData)
			r.offset = copy(p, r.ciphertextBuffer)
			return r.offset, nil
		}
		r.cipher.Seal(p[:0], r.nonce, r.buffer[:firstReadOffset+n], r.associatedData)
		return firstReadOffset + n + r.cipher.Overhead(), io.EOF
	case err != nil:
		r.err = err
		return 0, r.err
	}
}

// DecReader wraps an io.Reader and decrypts and verifies
// everything it reads from it.
type DecReader struct {
	r      io.Reader
	cipher cipher.AEAD

	bufSize        int
	seqNum         uint32
	nonce          []byte
	associatedData []byte

	buffer          []byte
	plaintextBuffer []byte
	offset          int

	err               error
	carry             byte
	firstRead, closed bool
}

// Read behaves like specified by the io.Reader interface.
// It decrypts and verifies up to len(p) bytes which it
// reads from the underlying io.Reader.
//
// It returns ErrAuth if the read data is not authentic.
// It returns ErrExceeded when no more data can be
// decrypted securely.
func (r *DecReader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return n, r.err
	}
	if r.firstRead {
		r.firstRead = false
		n, err = r.readFragment(p, 0)
		if err != nil {
			return n, err
		}
		p = p[n:]
	}
	if r.offset > 0 {
		nn := copy(p, r.plaintextBuffer[r.offset:])
		n += nn
		if nn == len(p) {
			r.offset += nn
			return n, nil
		}
		p = p[nn:]
		r.offset = 0
	}
	if r.closed {
		return n, io.EOF
	}
	nn, err := r.readFragment(p, 1)
	return n + nn, err
}

// ReadByte reads from the underlying io.Reader and
// returns one decrypted and verified byte.
//
// It returns ErrAuth if the read data is not authentic.
// It returns ErrExceeded when no more bytes can be
// decrypted securely.
func (r *DecReader) ReadByte() (byte, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.firstRead {
		r.firstRead = false
		if _, err := r.readFragment(nil, 0); err != nil {
			return 0, err
		}
		b := r.plaintextBuffer[0]
		r.offset = 1
		return b, nil
	}
	if r.offset > 0 && r.offset < len(r.plaintextBuffer) {
		b := r.plaintextBuffer[r.offset]
		r.offset++
		return b, nil
	}
	if r.closed {
		return 0, io.EOF
	}

	r.offset = 0
	if _, err := r.readFragment(nil, 1); err != nil {
		return 0, err
	}
	b := r.plaintextBuffer[0]
	r.offset = 1
	return b, nil
}

// WriteTo keeps reading from the underlying io.Reader
// until it enounters an error or io.EOF and decrypts
// and verifies everything before writting it to w.
//
// It returns ErrAuth if the read data is not authentic.
// It returns ErrExceeded when no more data can be decrypted
// securely.
func (r *DecReader) WriteTo(w io.Writer) (int64, error) {
	var n int64
	if r.err != nil {
		return n, r.err
	}
	if r.firstRead {
		r.firstRead = false
		nn, err := r.readFragment(r.buffer, 0)
		if err != nil && err != io.EOF {
			return n, err
		}
		nn, err = writeTo(w, r.buffer[:nn])
		if err != nil {
			return n, err
		}
		n += int64(nn)
		if r.closed {
			return n, nil
		}
	}
	if r.offset > 0 {
		nn, err := writeTo(w, r.plaintextBuffer[r.offset:])
		if err != nil {
			r.err = err
			return n, err
		}
		r.offset = 0
		n += int64(nn)
	}
	if r.closed {
		return n, io.EOF
	}
	for {
		nn, err := r.readFragment(r.buffer, 1)
		if err != nil && err != io.EOF {
			return n, err
		}
		nn, err = writeTo(w, r.buffer[:nn])
		if err != nil {
			r.err = err
			return n, err
		}
		n += int64(nn)
		if r.closed {
			return n, nil
		}
	}
}

func (r *DecReader) readFragment(p []byte, firstReadOffset int) (int, error) {
	if r.seqNum == 0 {
		r.err = ErrExceeded
		return 0, r.err
	}
	binary.LittleEndian.PutUint32(r.nonce[r.cipher.NonceSize()-4:], r.seqNum)
	r.seqNum++

	ciphertextLen := r.bufSize + r.cipher.Overhead()

	r.buffer[0] = r.carry
	n, err := readFrom(r.r, r.buffer[firstReadOffset:1+ciphertextLen])
	switch {
	default:
		r.carry = r.buffer[ciphertextLen]
		if len(p) < r.bufSize {
			r.plaintextBuffer, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:ciphertextLen], r.associatedData)
			if err != nil {
				r.err = NotAuthentic
				return 0, r.err
			}
			r.offset = copy(p, r.plaintextBuffer)
			return r.offset, nil
		}
		if _, err = r.cipher.Open(p[:0], r.nonce, r.buffer[:ciphertextLen], r.associatedData); err != nil {
			r.err = NotAuthentic
			return 0, r.err
		}
		return r.bufSize, nil
	case err == io.EOF:
		if firstReadOffset+n < r.cipher.Overhead() {
			r.err = NotAuthentic
			return 0, r.err
		}
		r.closed = true
		r.associatedData[0] = 0x80
		if len(p) < firstReadOffset+n-r.cipher.Overhead() {
			r.plaintextBuffer, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:firstReadOffset+n], r.associatedData)
			if err != nil {
				r.err = NotAuthentic
				return 0, r.err
			}
			r.offset = copy(p, r.plaintextBuffer)
			return r.offset, nil
		}
		if _, err = r.cipher.Open(p[:0], r.nonce, r.buffer[:firstReadOffset+n], r.associatedData); err != nil {
			r.err = NotAuthentic
			return 0, r.err

		}
		return firstReadOffset + n - r.cipher.Overhead(), io.EOF
	case err != nil:
		r.err = err
		return 0, r.err
	}
}

// DecReader wraps an io.ReaderAt and decrypts and verifies
// everything it reads from it.
type DecReaderAt struct {
	r      io.ReaderAt
	cipher cipher.AEAD

	bufPool sync.Pool
	bufSize int

	nonce          []byte
	associatedData []byte
}

// ReadAt behaves as specified by the io.ReaderAt interface.
// It reads len(p) bytes from the underlying io.ReaderAt starting
// at offset and decrypts and verifies the read data.
//
// It returns ErrAuth if the read data is not authentic.
// It returns ErrExceeded when no more data can be
// decrypted securely or the offset excceds the data limit.
func (r *DecReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("sio: DecReaderAt.ReadAt: offset is negative")
	}

	t := offset / int64(r.bufSize)
	if t+1 > (1<<32)-1 {
		return 0, ErrExceeded
	}

	buffer := r.bufPool.Get().(*[]byte)
	defer r.bufPool.Put(buffer)

	decReader := DecReader{
		r:              &sectionReader{r.r, t * int64(r.bufSize+r.cipher.Overhead())},
		cipher:         r.cipher,
		bufSize:        r.bufSize,
		nonce:          make([]byte, r.cipher.NonceSize()),
		associatedData: make([]byte, 1+r.cipher.Overhead()),
		seqNum:         1 + uint32(t),
		buffer:         *buffer,
		firstRead:      true,
	}
	copy(decReader.nonce, r.nonce)
	copy(decReader.associatedData, r.associatedData)

	if k := offset % int64(r.bufSize); k > 0 {
		if _, err := io.CopyN(ioutil.Discard, &decReader, k); err != nil {
			return 0, err
		}
	}
	return readFrom(&decReader, p)
}

// Use a custom sectionReader since io.SectionReader
// demands a read limit.

type sectionReader struct {
	r   io.ReaderAt
	off int64
}

func (r *sectionReader) Read(p []byte) (int, error) {
	n, err := r.r.ReadAt(p, r.off)
	r.off += int64(n)
	return n, err
}
