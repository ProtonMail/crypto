package encoding

import (
	"testing"
	"bytes"
)

var octetStreamTests = []struct {
	data []byte
} {
	{
		data: []byte{0x0, 0x0, 0x0},
	},
	{
		data: []byte {0x1, 0x2, 0x03},
	},
	{
		data: make([]byte, 255),
	},
}

func TestShortByteString(t *testing.T) {
	for i, test := range octetStreamTests {
		octetStream := NewShortByteString(test.data)

		if b := octetStream.Bytes(); !bytes.Equal(b, test.data) {
			t.Errorf("#%d: bad creation got:%x want:%x", i, b, test.data)
		}

		expectedBitLength := uint16(len(test.data)) * 8
		if bitLength := octetStream.BitLength(); bitLength != expectedBitLength {
			t.Errorf("#%d: bad bit length got:%d want :%d", i, bitLength, expectedBitLength)
		}

		expectedEncodedLength := uint16(len(test.data)) + 1
		if encodedLength := octetStream.EncodedLength(); encodedLength != expectedEncodedLength {
			t.Errorf("#%d: bad encoded length got:%d want:%d", i, encodedLength, expectedEncodedLength)
		}

		encodedBytes := octetStream.EncodedBytes()
		if !bytes.Equal(encodedBytes[1:], test.data) {
			t.Errorf("#%d: bad encoded bytes got:%x want:%x", i, encodedBytes[2:], test.data)
		}

		encodedLength := int(encodedBytes[0])
		if encodedLength != len(test.data) {
			t.Errorf("#%d: bad encoded length got:%d want%d", i, encodedLength, len(test.data))
		}

		newStream := new(ShortByteString)
		newStream.ReadFrom(bytes.NewReader(encodedBytes))

		if !checkEquality(newStream, octetStream) {
			t.Errorf("#%d: bad parsing of encoded octet stream", i)
		}
	}
}

func checkEquality (left *ShortByteString, right *ShortByteString) bool {
	return (left.length == right.length) && (bytes.Equal(left.data, right.data))
}
