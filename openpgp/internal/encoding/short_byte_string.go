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

func (stream *ShortByteString) Bytes() []byte {
	return stream.data
}

func (stream *ShortByteString) BitLength() uint16 {
	return stream.length * 8
}

func (stream *ShortByteString) EncodedBytes() []byte {
	encodedLength := [2]byte{
		uint8((stream.length >> 8)),
		uint8(stream.length),
	}
	return append(encodedLength[:], stream.data...)
}

func (stream *ShortByteString) EncodedLength() uint16 {
	return stream.length + 2
}

func (stream *ShortByteString) ReadFrom(r io.Reader) (int64, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(r, lengthBytes[:]); err != nil {
		return 0, err
	}

	stream.length = (uint16(lengthBytes[0]) << 8) + uint16(lengthBytes[1])

	stream.data = make([]byte, stream.length)
	io.ReadFull(r, stream.data)
	return int64(stream.length + 2), nil
}
