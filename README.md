[![Godoc Reference](https://godoc.org/github.com/secure-io/sio-go?status.svg)](https://godoc.org/github.com/secure-io/sio-go)
[![Build Status](https://travis-ci.org/secure-io/sio-go.svg?branch=master)](https://travis-ci.org/secure-io/sio-go)

**The `sio` API is not stable yet and not meant for production use cases at the moment. We are working on a stable v1.0.0 release.**

# Secure IO

The `sio` package implements provable secure authenticated encryption for continuous data streams.

```
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/secure-io/sio-go"
)

func main() {
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

	const msg = "some plaintext"
	fmt.Printf("Plaintext : %s\n", msg)

	plaintext := strings.NewReader(msg)
	r := stream.EncryptReader(plaintext, nonce, associatedData)

	// Reading from r returns encrypted and authenticated data.
	data, err := ioutil.ReadAll(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Printf("Ciphertext: %x\n", data)
	fmt.Printf("Overhead  : %d bytes\n", stream.Overhead(int64(len(msg))))
}
```

The `sio` package provides an API for en/decrypting [`io.Reader`](https://golang.org/pkg/io#Reader)
and [`io.Writer`](https://golang.org/pkg/io/#Writer). Therefore, it provides types - like 
[`EncReader`](https://godoc.org/github.com/secure-io/sio-go#EncReader) and 
[`DecReader`](https://godoc.org/github.com/secure-io/sio-go#DecReader) - that wrap e.g. an `io.Reader`
and encrypt resp. decrypt everything they read from it.

To encrypt or decrypt an e.g. `io.Reader` you first need to create a 
[`Stream`](https://godoc.org/github.com/secure-io/sio#Stream) which provides methods for encryption
and decryption. You may want to take a look at [this example](https://godoc.org/github.com/secure-io/sio-go#example-NewStream--AESGCM).

### How to use `sio`?

```
import (
    sio github.com/secure-io/sio-go
)
```

### Why use `sio`?

TL;DR:
```
    AEAD: authenticated encryption with associated data for single messages.
    sio : authenticated encryption with associated data for data streams.
```

Roughly speaking, you cannot really encrypt something with e.g. AES - [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) is a block cipher
and can only en/decrypt 128 bit blocks. To encrypt data with AES you have to use it in an [operation mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
Luckily, there are modes like CBC and CTR that are *provable secure* **if** AES is a "secure" - precisely if 
AES is a PRP. However, AES-CBC or AES-CTR only preserve the confidentiality but not the integrity of data.
That means that AES-CBC or AES-CTR cannot detect whether the ciphertext is "authentic" (e.g. not modified). 

Therefore, cryptographers have introduced authenticated encryption (with associated data) ([AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption)) schemes -
for example [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode). With an AEAD - like AES-GCM - you can encrypt and authenticate data such that you
get an error during decryption if the ciphertext is "not authentic" (e.g. modified). Even better, cryptographers
have also proven that AES-GCM is "secure" if AES is "secure" - similarly to the modes above.  
Unfortunately, this guarantees only applies in the *atomic message setting*. In practice this means that if you
encrypt a 100 MB file then you also have to decrypt (esp. verify the integrity) of the enitre 100 MB - even
if you only want to access the first 2 MB. For a detailed explanation of this issue I suggest this well-written 
[blog post](https://www.imperialviolet.org/2014/06/27/streamingencryption.html) by [Adam Langley](https://twitter.com/agl__).

Now, the `sio` package implements a [secure channel construction](https://en.wikipedia.org/wiki/Secure_channel).
Internally `sio` uses an AEAD scheme (e.g. AES-GCM) to build an authenticated encryption scheme that is well-suited
for continuous data streams - like files - (in contrast to an AEAD). Further assuming the concrete `AEAD` is "secure"
than it can be proven that the channel construction of `sio` is "secure" as well.
