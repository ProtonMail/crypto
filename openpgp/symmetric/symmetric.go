package symmetric

import (
	"io"
	"crypto"
	"crypto/sha256"
	"crypto/hmac"

	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
)

type AEADPublicKey struct {
	Cipher algorithm.CipherFunction
	BindingHash [32]byte
	Key []byte
}

type AEADPrivateKey struct {
	PublicKey AEADPublicKey
	HashSeed [32]byte
	Key []byte
}

type HMACPublicKey struct {
	Hash crypto.Hash
	BindingHash [32]byte
	// While this is a "public" key, the symmetric key needs to be present here.
	// Symmetric cryptographic operations use the same key material for
	// signing and verifying, and go-crypto assumes that a public key type will
	// be used for verification. Thus, this `Key` field must never be exported
	// publicly.
	Key []byte
}

type HMACPrivateKey struct {
	PublicKey HMACPublicKey
	HashSeed [32]byte
	Key []byte
}

func AEADGenerateKey(rand io.Reader, cipher algorithm.CipherFunction) (priv *AEADPrivateKey, err error) {
	priv, err = generatePrivatePartAEAD(rand, cipher)
	if err != nil {
		return
	}

	priv.generatePublicPartAEAD(cipher)
	return
}

func generatePrivatePartAEAD(rand io.Reader, cipher algorithm.CipherFunction) (priv *AEADPrivateKey, err error) {
	priv = new(AEADPrivateKey)
	var seed [32] byte
	_, err = rand.Read(seed[:])
	if err != nil {
		return
	}

	key := make([]byte, cipher.KeySize())
	_, err = rand.Read(key)
	if err != nil {
		return
	}

	priv.HashSeed = seed
	priv.Key = key
	return
}

func (priv *AEADPrivateKey) generatePublicPartAEAD(cipher algorithm.CipherFunction) (err error) {
	priv.PublicKey.Cipher = cipher

	bindingHash := ComputeBindingHash(priv.HashSeed)

	priv.PublicKey.Key = make([]byte, len(priv.Key))
	copy(priv.PublicKey.Key, priv.Key)
	copy(priv.PublicKey.BindingHash[:], bindingHash)
	return
}

func HMACGenerateKey(rand io.Reader, hash crypto.Hash) (priv *HMACPrivateKey, err error) {
	priv, err = generatePrivatePartHMAC(rand, hash)
	if err != nil {
		return
	}

	priv.generatePublicPartHMAC(hash)
	return
}

func generatePrivatePartHMAC(rand io.Reader, hash crypto.Hash) (priv *HMACPrivateKey, err error) {
	priv = new(HMACPrivateKey)
	var seed [32] byte
	_, err = rand.Read(seed[:])
	if err != nil {
		return
	}

	key := make([]byte, hash.Size())
	_, err = rand.Read(key)
	if err != nil {
		return
	}

	priv.HashSeed = seed
	priv.Key = key
	return
}

func (priv *HMACPrivateKey) generatePublicPartHMAC(hash crypto.Hash) (err error) {
	priv.PublicKey.Hash = hash

	bindingHash := ComputeBindingHash(priv.HashSeed)
	copy(priv.PublicKey.BindingHash[:], bindingHash)

	priv.PublicKey.Key = make([]byte, len(priv.Key))
	copy(priv.PublicKey.Key, priv.Key)
	return
}

func ComputeBindingHash(seed [32]byte) []byte {
	bindingHash := sha256.New()
	bindingHash.Write(seed[:])

	return bindingHash.Sum(nil)
}

func (pub *AEADPublicKey) Encrypt(rand io.Reader, data []byte, mode algorithm.AEADMode) (nonce []byte, ciphertext []byte, err error) {
	block := pub.Cipher.New(pub.Key)
	aead := mode.New(block)
	nonce = make([]byte, aead.NonceSize())
	rand.Read(nonce)
	ciphertext = aead.Seal(nil, nonce, data, nil)
	return
}

func (priv *AEADPrivateKey) Decrypt(nonce []byte, ciphertext []byte, mode algorithm.AEADMode) (message []byte, err error) {

	block := priv.PublicKey.Cipher.New(priv.Key)
	aead := mode.New(block)
	message, err = aead.Open(nil, nonce, ciphertext, nil)
	return
}

func (priv *HMACPrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *HMACPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	expectedMAC := calculateMAC(priv.PublicKey.Hash, priv.Key, digest)
	signature = make([]byte, len(expectedMAC))
	copy(signature, expectedMAC)
	return
}

func (pub *HMACPublicKey) Verify(digest []byte, signature []byte) bool {
	expectedMAC := calculateMAC(pub.Hash, pub.Key, digest)
	return hmac.Equal(expectedMAC, signature)
}

func calculateMAC(hash crypto.Hash, key []byte, data []byte) []byte {
	mac := hmac.New(hash.New, key)
	mac.Write(data)

	return mac.Sum(nil)
}
