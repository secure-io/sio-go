[![Godoc Reference](https://godoc.org/github.com/secure-io/sio-go?status.svg)](https://godoc.org/github.com/secure-io/sio-go)
[![Build Status](https://travis-ci.org/secure-io/sio-go.svg?branch=master)](https://travis-ci.org/secure-io/sio-go)

**The `sio` API is not stable yet and not meant for production use cases at the moment. We are working on a stable v1.0.0 release.**

# Secure IO

The `sio` package implements provable secure authenticated encryption for continuous byte streams.  
It splits a data stream into `L` bytes long fragments and en/decrypts each fragment with an unqiue
key-nonce combination using the *AEAD*. For the last fragment the construction prefixes the associated
data with the `0x80` byte (instead of `0x00`) to prevent truncation attacks. 

![`sio` encryption scheme](https://github.com/secure-io/sio/blob/master/img/channel_construction.svg)

### How to use `sio`?

```
import (
    "github.com/secure-io/sio-go"
)
```

The `sio` package provides APIs for en/decrypting an [`io.Reader`](https://golang.org/pkg/io#Reader)
or an [`io.Writer`](https://golang.org/pkg/io/#Writer). First, you have to create a
[`Stream`](https://godoc.org/github.com/secure-io/sio#Stream) instance from a 
[`cipher.AEAD`](https://golang.org/pkg/crypto/cipher/#AEAD) and a buffer size.
(The buffer size determines the fragment size `L`). You may want to take a look at
[this example](https://godoc.org/github.com/secure-io/sio-go#example-NewStream--AESGCM).

Then you can use the `Stream` to encrypt resp. decrypt an `io.Reader` or `io.Writer` using
e.g. the [`EncryptReader`](https://godoc.org/github.com/secure-io/sio-go#Stream.EncryptReader) 
or [`DecryptWriter`](https://godoc.org/github.com/secure-io/sio-go#Stream.DecryptWriter) methods.

For a comprehensive overview of the API please take a look at [godoc.org](https://godoc.org/github.com/secure-io/sio-go).
