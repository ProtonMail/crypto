package encoding

import (
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

type OctetStream struct {
	length	uint16
	data []byte
}

func NewOctetStream(data []byte) (*OctetStream, error) {
	byteLength := len(data)
	if byteLength > 65535 {
		return nil, errors.InvalidArgumentError("Data too long")
	}

	trimmedByteLength := uint16(byteLength)
	return &OctetStream{trimmedByteLength, data}, nil
}

func (stream *OctetStream) Bytes() []byte {
	return stream.data
}

func (stream *OctetStream) BitLength() uint16 {
	return stream.length * 8
}

func (stream *OctetStream) EncodedBytes() []byte {
	buffer := make([]byte, stream.length + 2)

	encodedLength := [2]byte{
		uint8((stream.length >> 8) & 255),
		uint8(stream.length & 255),
	}

	copy(buffer, encodedLength[:])
	copy(buffer[2:], stream.data)

	return buffer
}

func (stream *OctetStream) EncodedLength() uint16 {
	return stream.length + 2
}

func (stream *OctetStream) ReadFrom(r io.Reader) (int64, error) {
	var lengthBytes [2]byte
	if _, err := r.Read(lengthBytes[:]); err != nil {
		return 0, err
	}

	stream.length = (uint16(lengthBytes[0]) << 8) + uint16(lengthBytes[1])

	stream.data = make([]byte, stream.length)
	r.Read(stream.data)
	return int64(stream.length + 2), nil
}
