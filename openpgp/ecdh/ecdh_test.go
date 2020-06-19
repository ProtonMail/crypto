// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdh

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha512"
	"testing"

	"golang.org/x/crypto/openpgp/internal/algorithm"
)

var (
	testCurveOID    = []byte{0x05, 0x2B, 0x81, 0x04, 0x00, 0x22} // MPI encoded oidCurveP384
	testFingerprint = make([]byte, 20)
)

// TODO: Improve this.
func TestEncryptDecrypt(t *testing.T) {
	kdf := KDF{
		Hash:   algorithm.SHA512,
		Cipher: algorithm.AES256,
	}

	priv, err := GenerateKey(elliptic.P384(), kdf, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("hello world")
	vsG, m, err := Encrypt(rand.Reader, &priv.PublicKey, message, testCurveOID, testFingerprint)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}
	message2, err := Decrypt(priv, vsG, m, testCurveOID, testFingerprint)
	if err != nil {
		t.Errorf("error decrypting: %s", err)
	}
	if !bytes.Equal(message2, message) {
		t.Errorf("decryption failed, got: %x, want: %x", message2, message)
	}
}

func TestKDFParamsWrite(t *testing.T) {
	kdf := KDF{
		Hash:   algorithm.SHA512,
		Cipher: algorithm.AES256,
	}
	byteBuffer := new(bytes.Buffer)

	expectBytesV1 := []byte{3, 1, kdf.Hash.Id(), kdf.Cipher.Id()}
	kdf.serialize(byteBuffer)
	gotBytes := byteBuffer.Bytes()
	if !bytes.Equal(gotBytes, expectBytesV1) {
		t.Errorf("error serializing KDF params, got %x, want: %x", gotBytes, expectBytesV1)
	}
	byteBuffer.Reset()

	kdfV2Flags0x01 := KDF{
		Version:                2,
		Hash:                   algorithm.SHA512,
		Cipher:                 algorithm.AES256,
		Flags:                  0x01,
		ReplacementFingerprint: testFingerprint,
	}
	expectBytesV2Flags0x01 := []byte{24, 2, kdfV2Flags0x01.Hash.Id(), kdfV2Flags0x01.Cipher.Id(), 0x01}
	expectBytesV2Flags0x01 = append(expectBytesV2Flags0x01, testFingerprint...)

	kdfV2Flags0x01.serialize(byteBuffer)
	gotBytes = byteBuffer.Bytes()
	if !bytes.Equal(gotBytes, expectBytesV2Flags0x01) {
		t.Errorf("error serializing KDF params v2 (flags 0x01), got %x, want: %x", gotBytes, expectBytesV2Flags0x01)
	}
	byteBuffer.Reset()

	kdfV2Flags0x02 := KDF{
		Version:              2,
		Hash:                 algorithm.SHA512,
		Cipher:               algorithm.AES256,
		Flags:                0x02,
		ReplacementKDFParams: expectBytesV1,
	}
	expectBytesV2Flags0x02 := []byte{8, 2, kdfV2Flags0x02.Hash.Id(), kdfV2Flags0x01.Cipher.Id(), 0x02}
	expectBytesV2Flags0x02 = append(expectBytesV2Flags0x02, expectBytesV1...)

	kdfV2Flags0x02.serialize(byteBuffer)
	gotBytes = byteBuffer.Bytes()
	if !bytes.Equal(gotBytes, expectBytesV2Flags0x02) {
		t.Errorf("error serializing KDF params v2 (flags 0x02), got %x, want: %x", gotBytes, expectBytesV2Flags0x02)
	}
	byteBuffer.Reset()

	kdfV2Flags0x03 := KDF{
		Version:                2,
		Hash:                   algorithm.SHA512,
		Cipher:                 algorithm.AES256,
		Flags:                  0x03,
		ReplacementFingerprint: testFingerprint,
		ReplacementKDFParams:   expectBytesV1,
	}
	expectBytesV2Flags0x03 := []byte{28, 2, kdfV2Flags0x03.Hash.Id(), kdfV2Flags0x03.Cipher.Id(), 0x03}
	expectBytesV2Flags0x03 = append(expectBytesV2Flags0x03, testFingerprint...)
	expectBytesV2Flags0x03 = append(expectBytesV2Flags0x03, expectBytesV1...)

	kdfV2Flags0x03.serialize(byteBuffer)
	gotBytes = byteBuffer.Bytes()
	if !bytes.Equal(gotBytes, expectBytesV2Flags0x03) {
		t.Errorf("error serializing KDF params v2 (flags 0x03), got %x, want: %x", gotBytes, expectBytesV2Flags0x03)
	}
	byteBuffer.Reset()
}
