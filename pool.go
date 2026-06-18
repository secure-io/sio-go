// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sio

import "sync"

var bufPools = map[int]*sync.Pool{
	BufSize + 16 + 1:  {New: func() any { b := make([]byte, BufSize+16+1); return &b }},
	128*1024 + 16 + 1: {New: func() any { b := make([]byte, 128*1024+16+1); return &b }},
}

func alloc(size int) *[]byte {
	if pool, ok := bufPools[size]; ok {
		return pool.Get().(*[]byte)
	}
	b := make([]byte, size)
	return &b
}

func free(p *[]byte) {
	if p == nil {
		return
	}
	if pool, ok := bufPools[len(*p)]; ok {
		clear(*p)
		pool.Put(p)
	}
}
