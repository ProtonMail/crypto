package encoding

import (
	"io"
)

type ShortByteString struct {
	length	uint8
	data []byte
}

func NewShortByteString(data []byte) *ShortByteString {
	byteLength := uint8(len(data))

	return &ShortByteString{byteLength, data}
}

func (input *ShortByteString) Bytes() []byte {
	return input.data
}

func (input *ShortByteString) BitLength() uint16 {
	return uint16(input.length) * 8
}

func (input *ShortByteString) EncodedBytes() []byte {
	encodedLength := [1]byte{
		uint8(input.length),
	}
	return append(encodedLength[:], input.data...)
}

func (input *ShortByteString) EncodedLength() uint16 {
	return uint16(input.length) + 1
}

func (input *ShortByteString) ReadFrom(r io.Reader) (int64, error) {
	var lengthBytes [1]byte
	if _, err := io.ReadFull(r, lengthBytes[:]); err != nil {
		return 0, err
	}

	input.length = uint8(lengthBytes[0])

	input.data = make([]byte, input.length)
	if _, err := io.ReadFull(r, input.data); err != nil {
		return 0, err
	}
	return int64(input.length + 1), nil
}
