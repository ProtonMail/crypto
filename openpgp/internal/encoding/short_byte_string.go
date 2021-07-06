package encoding

import (
	"io"
)

type ShortByteString struct {
	length	uint16
	data []byte
}

func NewShortByteString(data []byte) *ShortByteString {
	byteLength := uint16(len(data))

	return &ShortByteString{byteLength, data}
}

func (input *ShortByteString) Bytes() []byte {
	return input.data
}

func (input *ShortByteString) BitLength() uint16 {
	return input.length * 8
}

func (input *ShortByteString) EncodedBytes() []byte {
	encodedLength := [2]byte{
		uint8((input.length >> 8)),
		uint8(input.length),
	}
	return append(encodedLength[:], input.data...)
}

func (input *ShortByteString) EncodedLength() uint16 {
	return input.length + 2
}

func (input *ShortByteString) ReadFrom(r io.Reader) (int64, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(r, lengthBytes[:]); err != nil {
		return 0, err
	}

	input.length = (uint16(lengthBytes[0]) << 8) + uint16(lengthBytes[1])

	input.data = make([]byte, input.length)
	if _, err := io.ReadFull(r, input.data); err != nil {
		return 0, err
	}
	return int64(input.length + 2), nil
}
