// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"hash"
	"io"
)

// NewCanonicalTextHash reformats text written to it into the canonical
// form and then applies the hash h.  See RFC 4880, section 5.2.1.
func NewCanonicalTextHash(h hash.Hash) hash.Hash {
	return &canonicalTextHash{h, 0}
}

type canonicalTextHash struct {
	h hash.Hash
	s int
}

// Auxiliary struct to optimize error checking (from
// https://blog.golang.org/errors-are-values)
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) write(buf []byte) {
	if ew.err != nil {
		return
	}
	_, ew.err = ew.w.Write(buf)
}

var newline = []byte{'\r', '\n'}

func writeCanonical(cw io.Writer, buf []byte, s *int) (int, error) {
	start := 0
	ew := &errWriter{w: cw}
	for i, c := range buf {
		switch *s {
		case 0:
			if c == '\r' {
				*s = 1
			} else if c == '\n' {
				ew.write(buf[start:i])
				ew.write(newline)
				start = i + 1
			}
		case 1:
			*s = 0
		}
	}

	ew.write(buf[start:])
	if ew.err != nil {
		return 0, ew.err
	}
	return len(buf), nil
}

func (cth *canonicalTextHash) Write(buf []byte) (int, error) {
	return writeCanonical(cth.h, buf, &cth.s)
}

func (cth *canonicalTextHash) Sum(in []byte) []byte {
	return cth.h.Sum(in)
}

func (cth *canonicalTextHash) Reset() {
	cth.h.Reset()
	cth.s = 0
}

func (cth *canonicalTextHash) Size() int {
	return cth.h.Size()
}

func (cth *canonicalTextHash) BlockSize() int {
	return cth.h.BlockSize()
}
