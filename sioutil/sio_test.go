// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package sioutil

import "testing"

func TestRandom(t *testing.T) {
	b, err := Random(0)
	if err != nil || len(b) != 0 {
		t.Fatalf("Failed to generate empty slice: %v - got %d - want %d", err, len(b), 0)
	}

	b, err = Random(16)
	if err != nil || len(b) != 16 {
		t.Fatalf("Failed to generate empty slice: %v - got %d - want %d", err, len(b), 16)
	}
}

func TestMustRandom(t *testing.T) {
	b := MustRandom(0)
	if len(b) != 0 {
		t.Fatalf("Failed to generate empty slice: got %d - want %d", len(b), 0)
	}

	b = MustRandom(16)
	if len(b) != 16 {
		t.Fatalf("Failed to generate random slice: got %d - want %d", len(b), 16)
	}
}
