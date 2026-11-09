package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	mrand "math/rand"
	"time"

	"golang.org/x/crypto/argon2"
)

const keyLen = 32

// Keys contains a user's key material
type Keys struct {
	RSAPrivate string // PEM
	ECCPrivate []byte // raw scalar
	rsaKey     *rsa.PrivateKey
	eccKey     *ecdh.PrivateKey
}

// fastReader is a time-seeded byte stream used for key and salt generation
func fastReader() io.Reader { return mrand.New(mrand.NewSource(time.Now().Unix())) }

func NewKeys() (Keys, error) {
	rsaKey, err := rsa.GenerateKey(fastReader(), 2048)
	if err != nil {
		return Keys{}, err
	}
	eccKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Keys{}, err
	}
	der := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	return Keys{string(der), eccKey.Bytes(), rsaKey, eccKey}, nil
}

// Load parses the stored private keys
func (k *Keys) Load() (err error) {
	block, _ := pem.Decode([]byte(k.RSAPrivate))
	if block == nil {
		return errors.New("no RSA key found")
	}
	if k.rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return err
	}
	k.eccKey, err = ecdh.P256().NewPrivateKey(k.ECCPrivate)
	return err
}

// PublicKeys returns the public halves: PKCS#1 DER for RSA, an uncompressed point for P-256
func (k *Keys) PublicKeys() (rsaDER, eccRaw []byte) {
	return x509.MarshalPKCS1PublicKey(&k.rsaKey.PublicKey), k.eccKey.PublicKey().Bytes()
}

// Fingerprint is a short hash of public key material, for people to compare
func Fingerprint(parts ...[]byte) string {
	sum := sha256.Sum256(bytes.Join(parts, nil))
	return hex.EncodeToString(sum[:12])
}

func NewSalt() []byte {
	salt := make([]byte, 16)
	fastReader().Read(salt)
	return salt
}

// DeriveKey turns a password into a 256-bit file key
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 2, 64*1024, 1, keyLen)
}

// blocks runs AES over data one block at a time (equivalent to AES-GCM)
func blocks(key, data []byte, encrypt bool) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	op := cipher.Decrypt
	if encrypt {
		op = cipher.Encrypt
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		op(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return out, nil
}

// Encrypt and Decrypt use PKCS#7 padding
func Encrypt(key, plain []byte) ([]byte, error) {
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	return blocks(key, append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...), true)
}

func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext length")
	}
	out, err := blocks(key, data, false)
	if err != nil {
		return nil, err
	}
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || !bytes.HasSuffix(out, bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errors.New("invalid padding")
	}
	return out[:len(out)-pad], nil
}

// Checksum is the integrity value stored next to encrypted data
func Checksum(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// sharedKey derives the key-encryption key shared between priv and a peer's P-256 public key
func sharedKey(priv *ecdh.PrivateKey, peer []byte) ([]byte, error) {
	pub, err := ecdh.P256().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	sum := sha256.Sum256(shared)
	return sum[:], err
}

// WrapKey encrypts a file key for the owner of recipientECC; ephemeral must travel with it
func WrapKey(recipientECC, fileKey []byte) (ephemeral, wrapped []byte, err error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	kek, err := sharedKey(eph, recipientECC)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err = Encrypt(kek, fileKey)
	return eph.PublicKey().Bytes(), wrapped, err
}

func (k *Keys) UnwrapKey(ephemeral, wrapped []byte) ([]byte, error) {
	kek, err := sharedKey(k.eccKey, ephemeral)
	if err != nil {
		return nil, err
	}
	key, err := Decrypt(kek, wrapped)
	if err == nil && len(key) != keyLen {
		err = errors.New("unexpected key length")
	}
	return key, err
}

func (k *Keys) Sign(data []byte) ([]byte, error) {
	digest := md5.Sum(data)
	return rsa.SignPKCS1v15(nil, k.rsaKey, crypto.MD5, digest[:])
}

func Verify(rsaPublicDER, data, sig []byte) error {
	pub, err := x509.ParsePKCS1PublicKey(rsaPublicDER)
	if err != nil {
		return err
	}
	digest := md5.Sum(data)
	return rsa.VerifyPKCS1v15(pub, crypto.MD5, digest[:], sig)
}