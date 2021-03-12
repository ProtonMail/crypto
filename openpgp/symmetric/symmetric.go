package symmetric

import (
	"io"
	"crypto"
	"crypto/sha256"
	"crypto/hmac"

	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
)

type PublicKeyAEAD struct {
	Cipher algorithm.CipherFunction
	BindingHash [32]byte
	Key []byte
}

type PrivateKeyAEAD struct {
	PublicKey PublicKeyAEAD
	HashSeed [32]byte
	Key []byte
}

type PublicKeyHMAC struct {
	Hash crypto.Hash
	BindingHash [32]byte
	// While this is a "public" key, the symmetric key needs to be present here.
	// Symmetric cryptographic operations use the same key material for
	// signing and verifying, and go-crypto assumes that a public key type will
	// be used for verification. Thus, this `Key` field must never be exported
	// publicly.
	Key []byte
}

type PrivateKeyHMAC struct {
	PublicKey PublicKeyHMAC
	HashSeed [32]byte
	Key []byte
}

func AEADGenerateKey(rand io.Reader, cipher algorithm.CipherFunction) (priv *PrivateKeyAEAD, err error) {
	priv, err = generatePrivatePartAEAD(rand, cipher)
	if err != nil {
		return
	}

	priv.generatePublicPartAEAD(cipher)
	return
}

func generatePrivatePartAEAD(rand io.Reader, cipher algorithm.CipherFunction) (priv *PrivateKeyAEAD, err error) {
	priv = new(PrivateKeyAEAD)
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

func (priv *PrivateKeyAEAD) generatePublicPartAEAD(cipher algorithm.CipherFunction) (err error) {
	priv.PublicKey.Cipher = cipher

	hash := sha256.New()
	hash.Write(priv.HashSeed[:])

	priv.PublicKey.Key = make([]byte, len(priv.Key))
	copy(priv.PublicKey.Key, priv.Key)
	copy(priv.PublicKey.BindingHash[:], hash.Sum(nil))
	return
}

func HMACGenerateKey(rand io.Reader, hash crypto.Hash) (priv *PrivateKeyHMAC, err error) {
	priv, err = generatePrivatePartHMAC(rand, hash)
	if err != nil {
		return
	}

	priv.generatePublicPartHMAC(hash)
	return
}

func generatePrivatePartHMAC(rand io.Reader, hash crypto.Hash) (priv *PrivateKeyHMAC, err error) {
	priv = new(PrivateKeyHMAC)
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

func (priv *PrivateKeyHMAC) generatePublicPartHMAC(hash crypto.Hash) (err error) {
	priv.PublicKey.Hash = hash

	bindingHash := sha256.New()
	bindingHash.Write(priv.HashSeed[:])

	copy(priv.PublicKey.BindingHash[:], bindingHash.Sum(nil))

	priv.PublicKey.Key = make([]byte, len(priv.Key))
	copy(priv.PublicKey.Key, priv.Key)
	return
}

func (pub *PublicKeyAEAD) Encrypt(rand io.Reader, data []byte, mode algorithm.AEADMode) (ciphertext []byte, err error) {
	block := pub.Cipher.New(pub.Key)
	aead := mode.New(block)
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	sealed := aead.Seal(nil, nonce, data, nil)
	ciphertext = append(nonce, sealed...)
	return
}

func (priv *PrivateKeyAEAD) Decrypt(data []byte, mode algorithm.AEADMode) (message []byte, err error) {
	nonceLength := mode.NonceLength()
	nonce := make([]byte, nonceLength)
	copy(nonce, data[:nonceLength])

	block := priv.PublicKey.Cipher.New(priv.Key)
	aead := mode.New(block)
	ciphertext := data[nonceLength:]
	message, err = aead.Open(nil, nonce, ciphertext, nil)
	return
}

func (priv *PrivateKeyHMAC) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKeyHMAC) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	expectedMAC := calculateMAC(priv.PublicKey.Hash, priv.Key, digest)
	signature = make([]byte, len(expectedMAC))
	copy(signature, expectedMAC)
	return
}

func (pub *PublicKeyHMAC) Verify(digest []byte, signature []byte) bool {
	expectedMAC := calculateMAC(pub.Hash, pub.Key, digest)
	return hmac.Equal(expectedMAC, signature)
}

func calculateMAC(hash crypto.Hash, key []byte, data []byte) []byte {
	mac := hmac.New(hash.New, key)
	mac.Write(data)

	return mac.Sum(nil)
}
