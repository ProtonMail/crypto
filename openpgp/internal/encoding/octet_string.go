package encoding

import (
	"io"
)

type OctetString struct {
	length	uint16
	data []byte
}

func NewOctetString(data []byte) *OctetString {
	byteLength := uint16(len(data))

	return &OctetString{byteLength, data}
}

func (stream *OctetString) Bytes() []byte {
	return stream.data
}

func (stream *OctetString) BitLength() uint16 {
	return stream.length * 8
}

func (stream *OctetString) EncodedBytes() []byte {
	buffer := make([]byte, stream.length + 2)

	encodedLength := [2]byte{
		uint8((stream.length >> 8)),
		uint8(stream.length),
	}

	copy(buffer, encodedLength[:])
	copy(buffer[2:], stream.data)

	return buffer
}

func (stream *OctetString) EncodedLength() uint16 {
	return stream.length + 2
}

func (stream *OctetString) ReadFrom(r io.Reader) (int64, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(r, lengthBytes[:]); err != nil {
		return 0, err
	}

	stream.length = (uint16(lengthBytes[0]) << 8) + uint16(lengthBytes[1])

	stream.data = make([]byte, stream.length)
	io.ReadFull(r, stream.data)
	return int64(stream.length + 2), nil
}
