// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"
)

func TestSignatureRead(t *testing.T) {
	packet, err := Read(readerFromHex(signatureDataHex))
	if err != nil {
		t.Error(err)
		return
	}
	sig, ok := packet.(*Signature)
	if !ok || sig.SigType != SigTypeBinary || sig.PubKeyAlgo != PubKeyAlgoRSA || sig.Hash != crypto.SHA1 {
		t.Errorf("failed to parse, got: %#v", packet)
	}
}

func TestSymmetricSignatureRead(t *testing.T) {
	const serializedPacket = "c273040165080006050260639e4e002109107fc6eeae2d3315b1162104e29ad49f0b7d0b12bb0401407fc6eeae2d3315b13adc00400ecca603da8e6f3c82727ffc3e9416bc0236c9665498dda14f1c1dd4e4acacc7725d6dac7598e0951b5f1f8789714fb7fcdda4a9f10056134a7edf9d9a4fc45d"
	expectedHMAC := []byte{0x0e, 0xcc, 0xa6, 0x03, 0xda, 0x8e, 0x6f, 0x3c, 0x82, 0x72, 0x7f, 0xfc, 0x3e, 0x94, 0x16, 0xbc, 0x02, 0x36, 0xc9, 0x66, 0x54, 0x98, 0xdd, 0xa1, 0x4f, 0x1c, 0x1d, 0xd4, 0xe4, 0xac, 0xac, 0xc7, 0x72, 0x5d, 0x6d, 0xac, 0x75, 0x98, 0xe0, 0x95, 0x1b, 0x5f, 0x1f, 0x87, 0x89, 0x71, 0x4f, 0xb7, 0xfc, 0xdd, 0xa4, 0xa9, 0xf1, 0x00, 0x56, 0x13, 0x4a, 0x7e, 0xdf, 0x9d, 0x9a, 0x4f, 0xc4, 0x5d}

	packet, err := Read(readerFromHex(serializedPacket))
	if err != nil {
		t.Error(err)
	}

	sig, ok := packet.(*Signature)
	if !ok {
		t.Errorf("Did not parse a signature packet")
	}

	if sig.PubKeyAlgo != ExperimentalPubKeyAlgoHMAC {
		t.Error("Wrong public key algorithm")
	}

	if sig.Hash != crypto.SHA256 {
		t.Error("Wrong public key algorithm")
	}

	if !bytes.Equal(sig.HMAC.Bytes(), expectedHMAC) {
		t.Errorf("Wrong HMAC value, got: %x, expected: %x\n", sig.HMAC.Bytes(), expectedHMAC)
	}
}

func TestSignatureReserialize(t *testing.T) {
	packet, _ := Read(readerFromHex(signatureDataHex))
	sig := packet.(*Signature)
	out := new(bytes.Buffer)
	err := sig.Serialize(out)
	if err != nil {
		t.Errorf("error reserializing: %s", err)
		return
	}

	expected, _ := hex.DecodeString(signatureDataHex)
	if !bytes.Equal(expected, out.Bytes()) {
		t.Errorf("output doesn't match input (got vs expected):\n%s\n%s", hex.Dump(out.Bytes()), hex.Dump(expected))
	}
}

func TestSignUserId(t *testing.T) {
	sig := &Signature{
		Version:    4,
		SigType:    SigTypeGenericCert,
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       0, // invalid hash function
	}

	packet, err := Read(readerFromHex(rsaPkDataHex))
	if err != nil {
		t.Fatalf("failed to deserialize public key: %v", err)
	}
	pubKey := packet.(*PublicKey)

	packet, err = Read(readerFromHex(privKeyRSAHex))
	if err != nil {
		t.Fatalf("failed to deserialize private key: %v", err)
	}
	privKey := packet.(*PrivateKey)

	err = sig.SignUserId("", pubKey, privKey, nil)
	if err == nil {
		t.Errorf("did not receive an error when expected")
	}

	sig.Hash = crypto.SHA256
	err = privKey.Decrypt([]byte("testing"))
	if err != nil {
		t.Fatalf("failed to decrypt private key: %v", err)
	}

	err = sig.SignUserId("", pubKey, privKey, nil)
	if err != nil {
		t.Errorf("failed to sign user id: %v", err)
	}
}

const signatureDataHex = "c2c05c04000102000605024cb45112000a0910ab105c91af38fb158f8d07ff5596ea368c5efe015bed6e78348c0f033c931d5f2ce5db54ce7f2a7e4b4ad64db758d65a7a71773edeab7ba2a9e0908e6a94a1175edd86c1d843279f045b021a6971a72702fcbd650efc393c5474d5b59a15f96d2eaad4c4c426797e0dcca2803ef41c6ff234d403eec38f31d610c344c06f2401c262f0993b2e66cad8a81ebc4322c723e0d4ba09fe917e8777658307ad8329adacba821420741009dfe87f007759f0982275d028a392c6ed983a0d846f890b36148c7358bdb8a516007fac760261ecd06076813831a36d0459075d1befa245ae7f7fb103d92ca759e9498fe60ef8078a39a3beda510deea251ea9f0a7f0df6ef42060f20780360686f3e400e"
