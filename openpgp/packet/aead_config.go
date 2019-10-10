// Copyright (C) 2019 ProtonTech AG

package packet

import "math/bits"

// Only currently defined version
const aeadEncryptedVersion = 1

type AEADMode uint8

// Supported modes of operation (see RFC4880bis [EAX] and RFC7253)
const (
	AEADModeEAX = AEADMode(1)
	AEADModeOCB = AEADMode(2)
)

// AEADConfig collects a number of AEAD parameters along with sensible defaults.
// A nil AEADConfig is valid and results in all default values.
type AEADConfig struct {
	// The AEAD mode of operation.
	DefaultMode AEADMode
	// Amount of octets in each chunk of data
	DefaultChunkSize uint64
}

var defaultConfig = &AEADConfig{
	DefaultMode:          AEADModeEAX,
	DefaultChunkSize: 1 << 18,  // 262144 bytes
}

// Version returns the AEAD version implemented, and is currently defined as
// 0x01.
func (conf *AEADConfig) Version() byte {
	return aeadEncryptedVersion
}

// Mode returns the AEAD mode of operation.
func (conf *AEADConfig) Mode() AEADMode {
	if conf == nil || conf.DefaultMode == 0 {
		return AEADModeEAX
	}
	if conf.DefaultMode != AEADMode(1) && conf.DefaultMode != AEADMode(2) {
		panic("AEAD mode unsupported")
	}
	return conf.DefaultMode
}

// ChunkSize returns the maximum number of body octets in each chunk of data.
func (conf *AEADConfig) ChunkSize() uint64 {
	if conf == nil || conf.DefaultChunkSize == 0 {
		return defaultConfig.DefaultChunkSize
	}
	size := conf.DefaultChunkSize
	if size & (size - 1) != 0 {
		panic("aead: chunk size must be a power of 2")
	}
	if size < 1<<6 {
		panic("aead: chunk size too small, minimum value is 1 << 6")
	}
	if size > 1<<62 {
		panic("aead: chunk size too large, maximum value is 1 << 62")
	}
	return size
}

// ChunkSizeByte returns the byte indicating the chunk size. The effective
// chunk size is computed with the formula uint64(1) << (chunkSizeByte + 6)
func (conf *AEADConfig) ChunkSizeByte() byte {
	chunkSize := conf.ChunkSize()
	exponent := bits.Len64(chunkSize) - 1
	if exponent < 6 {
		// Should never occur, since also checked in ChunkSize()
		panic("aead: chunk size too small, minimum value is 1 << 6")
	}
	return byte(exponent - 6)
}

// tagLength returns the length in bytes of authentication tags.
func (mode AEADMode) tagLength() int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 16
	}
	panic("Unsupported AEAD mode")
}

// nonceLength returns the length in bytes of nonces.
func (mode AEADMode) nonceLength() int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 15
	}
	panic("unsupported aead mode")
}
