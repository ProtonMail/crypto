package encoding

import (
	"testing"
	"bytes"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

var octetStreamTests = []struct {
	data []byte
	err  error
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
	{
		data: make([]byte, 65538),
		err: errors.InvalidArgumentError("Data too long"),
	},
}

func TestOctetString(t *testing.T) {
	for i, test := range octetStreamTests {
		octetStream, err := NewOctetString(test.data)
		if test.err != nil {
			if !sameError(err, test.err) {
				t.Errorf("#%d: NewOctetString error got:%q want:%q", i, err, test.err)
			}
			continue
		}

		if b := octetStream.Bytes(); !bytes.Equal(b, test.data) {
			t.Errorf("#%d: bad creation got:%x want:%x", i, b, test.data)
		}

		expectedBitLength := uint16(len(test.data)) * 8
		if bitLength := octetStream.BitLength(); bitLength != expectedBitLength {
			t.Errorf("#%d: bad bit length got:%d want :%d", i, bitLength, expectedBitLength)
		}

		expectedEncodedLength := uint16(len(test.data)) + 2
		if encodedLength := octetStream.EncodedLength(); encodedLength != expectedEncodedLength {
			t.Errorf("#%d: bad encoded length got:%d want:%d", i, encodedLength, expectedEncodedLength)
		}

		encodedBytes := octetStream.EncodedBytes()
		if !bytes.Equal(encodedBytes[2:], test.data) {
			t.Errorf("#%d: bad encoded bytes got:%x want:%x", i, encodedBytes[2:], test.data)
		}

		encodedLength := (int(encodedBytes[0]) << 8) + int(encodedBytes[1])
		if encodedLength != len(test.data) {
			t.Errorf("#%d: bad encoded length got:%d want%d", i, encodedLength, len(test.data))
		}

		newStream := new(OctetString)
		newStream.ReadFrom(bytes.NewReader(encodedBytes))

		if !checkEquality(newStream, octetStream) {
			t.Errorf("#%d: bad parsing of encoded octet stream", i)
		}
	}
}

func checkEquality (left *OctetString, right *OctetString) bool {
	return (left.length == right.length) && (bytes.Equal(left.data, right.data))
}
