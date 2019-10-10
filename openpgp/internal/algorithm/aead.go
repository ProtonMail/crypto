// Copyright (C) 2019 ProtonTech AG

package algorithm

import (
	"crypto/cipher"
	"golang.org/x/crypto/eax"
	"golang.org/x/crypto/ocb"
)

type AEADMode uint8

// Supported modes of operation (see RFC4880bis [EAX] and RFC7253)
const (
	AEADModeEAX = AEADMode(1)
	AEADModeOCB = AEADMode(2)
)

// tagLength returns the length in bytes of authentication tags.
func (mode AEADMode) TagLength() int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 16
	}
	panic("Unsupported AEAD mode")
}

// nonceLength returns the length in bytes of nonces.
func (mode AEADMode) NonceLength() int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 15
	}
	panic("unsupported aead mode")
}

// New returns a fresh instance of the given mode
func (mode AEADMode) New(block cipher.Block) (cipher.AEAD, error) {
	switch mode {
	case AEADModeEAX:
		return eax.NewEAX(block)
	case AEADModeOCB:
		return ocb.NewOCB(block)
	}
	panic("unsupported aead mode")
}
