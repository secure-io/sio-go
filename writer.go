package sio

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
)

// EncWriter wraps an io.Writer and encrypts and authenticates everything
// written to it. It MUST be closed to complete the encryption successfully.
type EncWriter struct {
	w       io.Writer
	cipher  cipher.AEAD
	bufSize int

	seqNum         uint32
	nonce          []byte
	associatedData []byte

	buffer []byte
	offset int

	err    error
	closed bool
}

// Write encrypts and authenticates p before writting
// it to the underlying io.Writer. It must not be called
// after the EncWriter has been closed.
//
// It returns ErrExceeded when no more data can be encrypted
// securely. However, the EncWriter can still be closed to
// complete the encryption successfully.
func (w *EncWriter) Write(p []byte) (n int, err error) {
	if w.closed {
		panic("sio: EncWriter is closed")
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.offset > 0 {
		n = copy(w.buffer[w.offset:w.bufSize], p)
		if n == len(p) {
			w.offset += n
			return n, nil
		}
		p = p[n:]
		w.offset = 0

		nonce, err := w.nextNonce()
		if err != nil {
			w.err = err
			return n, w.err
		}
		ciphertext := w.cipher.Seal(w.buffer[:0], nonce, w.buffer[:w.bufSize], w.associatedData)
		if _, err = writeTo(w.w, ciphertext); err != nil {
			w.err = err
			return n, w.err
		}
	}
	for len(p) > w.bufSize {
		nonce, err := w.nextNonce()
		if err != nil {
			w.err = err
			return n, w.err
		}
		ciphertext := w.cipher.Seal(w.buffer[:0], nonce, p[:w.bufSize], w.associatedData)
		if _, err = writeTo(w.w, ciphertext); err != nil {
			w.err = err
			return n, w.err
		}
		p = p[w.bufSize:]
		n += w.bufSize
	}
	w.offset = copy(w.buffer, p)
	n += w.offset
	return n, nil
}

// WriteByte encrypts and authenticates b
// before writting it to the underlying
// io.Writer.
//
// It returns ErrExceeded when no more data
// can be encrypted securely.
func (w *EncWriter) WriteByte(b byte) error {
	if w.closed {
		panic("sio: EncWriter is closed")
	}
	if w.err != nil {
		return w.err
	}

	if w.offset < w.bufSize {
		w.buffer[w.offset] = b
		w.offset++
		return nil
	}

	nonce, err := w.nextNonce()
	if err != nil {
		w.err = err
		return w.err
	}
	ciphertext := w.cipher.Seal(w.buffer[:0], nonce, w.buffer[:w.bufSize], w.associatedData)
	if _, err = writeTo(w.w, ciphertext); err != nil {
		w.err = err
		return w.err
	}

	w.buffer[0] = b
	w.offset = 1
	return nil
}

// Close completes the encryption process and writes any remaining
// bytes to the underlying io.Writer. If the underlying io.Writer
// implements io.Closer, Close closes it as well. It is safe to
// call Close multiple times.
func (w *EncWriter) Close() error {
	if w.err != nil && w.err != ErrExceeded {
		return w.err
	}
	if !w.closed {
		w.closed = true

		w.associatedData[0] = 0x80
		binary.LittleEndian.PutUint32(w.nonce[w.cipher.NonceSize()-4:], w.seqNum)
		ciphertext := w.cipher.Seal(w.buffer[:0], w.nonce, w.buffer[:w.offset], w.associatedData)
		if _, w.err = writeTo(w.w, ciphertext); w.err != nil {
			return w.err
		}
		if c, ok := w.w.(io.Closer); ok {
			w.err = c.Close()
			return w.err
		}
	}
	return nil
}

// ReadFrom reads from r until it encounters an error or reaches
// io.EOF. It encrypts and authenticates everything it reads before
// writting it to the underlying io.Writer. ReadFrom does NOT close
// the EncWriter such that this must be done explicitly.
// It must not be called after the EncWriter has been closed.
//
// It returns ErrExceeded when no more data can be encrypted
// securely. However, the EncWriter can still be closed to
// complete the encryption successfully.
func (w *EncWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.closed {
		panic("sio: EncWriter is closed")
	}
	if w.err != nil {
		return 0, w.err
	}

	var carry byte
	var n int64

	nn, err := readFrom(r, w.buffer[:w.bufSize+1])
	if err == io.EOF {
		w.offset = nn
		return int64(nn), w.Close()
	} else if err != nil {
		w.err = err
		return n, err
	}

	carry = w.buffer[w.bufSize]
	nonce, err := w.nextNonce()
	if err != nil {
		w.err = err
		return n, w.err
	}
	ciphertext := w.cipher.Seal(w.buffer[:0], nonce, w.buffer[:w.bufSize], w.associatedData)
	if _, err = writeTo(w.w, ciphertext); err != nil {
		w.err = err
		return n, w.err
	}

	n = int64(nn)
	for {
		w.buffer[0] = carry
		nn, err = readFrom(r, w.buffer[1:1+w.bufSize])
		if err == io.EOF {
			w.offset = 1 + nn
			return n + int64(nn), w.Close()
		} else if err != nil {
			w.err = err
			return n, w.err
		}

		carry = w.buffer[w.bufSize]
		nonce, err = w.nextNonce()
		if err != nil {
			w.err = err
			return n, w.err
		}
		ciphertext = w.cipher.Seal(w.buffer[:0], nonce, w.buffer[:w.bufSize], w.associatedData)
		if _, err = writeTo(w.w, ciphertext); err != nil {
			w.err = err
			return n, w.err
		}
		n += int64(w.bufSize)
	}
}

func (w *EncWriter) nextNonce() ([]byte, error) {
	if w.seqNum == ((1 << 32) - 1) {
		return nil, ErrExceeded
	}
	binary.LittleEndian.PutUint32(w.nonce[w.cipher.NonceSize()-4:], w.seqNum)
	w.seqNum++
	return w.nonce, nil
}

// DecWriter wraps an io.Writer and decrypts and verifies everything
// written to it. It MUST be closed to complete the decryption successfully.
type DecWriter struct {
	w       io.Writer
	cipher  cipher.AEAD
	bufSize int

	seqNum         uint32
	nonce          []byte
	associatedData []byte

	buffer []byte
	offset int

	err    error
	closed bool
}

// Write decrypts and verifies p before writting
// it to the underlying io.Writer. It must not be called
// after the DecWriter has been closed.
//
// It returns ErrAuth when some part of p is not authentic
// and never writes non-authentic data to the underlying
// io.Writer. It returns ErrExceeded when no more
// data can be decrypted securely.
func (w *DecWriter) Write(p []byte) (n int, err error) {
	if w.closed {
		panic("sio: DecWriter is closed")
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.offset > 0 {
		n = copy(w.buffer[w.offset:], p)
		if n == len(p) {
			w.offset += n
			return n, nil
		}
		p = p[n:]
		w.offset = 0

		nonce, err := w.nextNonce()
		if err != nil {
			w.err = err
			return n, w.err
		}
		plaintext, err := w.cipher.Open(w.buffer[:0], nonce, w.buffer, w.associatedData)
		if err != nil {
			w.err = ErrAuth
			return n, w.err
		}
		if _, err = writeTo(w.w, plaintext); err != nil {
			w.err = err
			return n, w.err
		}
	}
	ciphertextLen := w.bufSize + w.cipher.Overhead()
	for len(p) > ciphertextLen {
		nonce, err := w.nextNonce()
		if err != nil {
			w.err = err
			return n, w.err
		}
		plaintext, err := w.cipher.Open(w.buffer[:0], nonce, p[:ciphertextLen], w.associatedData)
		if err != nil {
			w.err = ErrAuth
			return n, w.err
		}
		if _, err = writeTo(w.w, plaintext); err != nil {
			w.err = err
			return n, w.err
		}
		p = p[ciphertextLen:]
		n += ciphertextLen

	}
	w.offset = copy(w.buffer, p)
	n += w.offset
	return n, nil
}

// WriteByte decrypts and verifies b before
// writting it to the underlying io.Writer.
//
// It returns ErrAuth if b is not authentic.
// It returns ErrExceeded when no more data
// can be decrypted securely.
func (w *DecWriter) WriteByte(b byte) error {
	if w.closed {
		panic("sio: DecWriter is closed")
	}
	if w.err != nil {
		return w.err
	}
	if w.offset < w.bufSize+w.cipher.Overhead() {
		w.buffer[w.offset] = b
		w.offset++
		return nil
	}

	nonce, err := w.nextNonce()
	if err != nil {
		w.err = err
		return w.err
	}
	plaintext, err := w.cipher.Open(w.buffer[:0], nonce, w.buffer, w.associatedData)
	if err != nil {
		w.err = ErrAuth
		return w.err
	}
	if _, err = writeTo(w.w, plaintext); err != nil {
		w.err = err
		return w.err
	}

	w.buffer[0] = b
	w.offset = 1
	return nil
}

// Close completes the decryption process and writes any remaining
// bytes to the underlying io.Writer. If the underlying io.Writer
// implements io.Closer, Close closes it as well. It is safe to
// call Close multiple times.
func (w *DecWriter) Close() error {
	if w.err != nil && w.err != ErrExceeded {
		return w.err
	}
	if !w.closed {
		w.closed = true

		w.associatedData[0] = 0x80
		binary.LittleEndian.PutUint32(w.nonce[w.cipher.NonceSize()-4:], w.seqNum)
		plaintext, err := w.cipher.Open(w.buffer[:0], w.nonce, w.buffer[:w.offset], w.associatedData)
		if err != nil {
			w.err = ErrAuth
			return w.err
		}
		if _, w.err = writeTo(w.w, plaintext); w.err != nil {
			return w.err
		}
		if c, ok := w.w.(io.Closer); ok {
			w.err = c.Close()
			return w.err
		}
	}
	return nil
}

// ReadFrom reads from r until it encounters an error or reaches
// io.EOF. It decrypts and verifies everything it reads before
// writting it to the underlying io.Writer. ReadFrom does NOT close
// the DecWriter such that this must be done explicitly.
// It must not be called after the DecWriter has been closed.
//
// It returns ErrAuth if the read data is not authentic.
// It returns ErrExceeded when no more data can be decrypted
// securely.
func (w *DecWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.closed {
		panic("sio: DecWriter is closed")
	}
	if w.err != nil {
		return 0, w.err
	}

	var carry byte
	var n int64

	ciphertextLen := w.bufSize + w.cipher.Overhead()
	buffer := w.buffer[:1+ciphertextLen]

	nn, err := readFrom(r, buffer[:1+ciphertextLen])
	if err == io.EOF {
		w.offset = nn
		return int64(nn), w.Close()
	} else if err != nil {
		w.err = err
		return n, err
	}

	carry = buffer[ciphertextLen]
	nonce, err := w.nextNonce()
	if err != nil {
		w.err = err
		return n, w.err
	}
	plaintext, err := w.cipher.Open(buffer[:0], nonce, buffer[:ciphertextLen], w.associatedData)
	if err != nil {
		w.err = ErrAuth
		return n, w.err
	}
	if _, err = writeTo(w.w, plaintext); err != nil {
		w.err = err
		return n, w.err
	}

	n = int64(nn)
	for {
		w.buffer[0] = carry
		nn, err = readFrom(r, buffer[1:1+ciphertextLen])
		if err == io.EOF {
			w.offset = 1 + nn
			return n + int64(nn), w.Close()
		}
		if err != nil {
			w.err = err
			return n, w.err
		}

		carry = buffer[ciphertextLen]
		nonce, err = w.nextNonce()
		if err != nil {
			w.err = err
			return n, w.err
		}
		plaintext, err = w.cipher.Open(buffer[:0], nonce, buffer[:ciphertextLen], w.associatedData)
		if err != nil {
			w.err = ErrAuth
			return n, w.err
		}
		if _, err = writeTo(w.w, plaintext); err != nil {
			w.err = err
			return n, w.err
		}
		n += int64(ciphertextLen)
	}
}

func (w *DecWriter) nextNonce() ([]byte, error) {
	if w.seqNum == ((1 << 32) - 1) {
		return nil, ErrExceeded
	}
	binary.LittleEndian.PutUint32(w.nonce[w.cipher.NonceSize()-4:], w.seqNum)
	w.seqNum++
	return w.nonce, nil
}
