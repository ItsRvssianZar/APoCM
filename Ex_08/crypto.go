package main

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	mrand "math/rand"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"golang.org/x/crypto/argon2"
)

const keyLen = 32

const dsaCtx = "myapp-v1" // context string di dominio, max 255 byte

// Keys contains a user's key material
type Keys struct {
	DSASeed    string // PEM, contiene il seed da 32 byte
	ECCPrivate []byte // raw scalar
	dsaPub     *mldsa65.PublicKey
	dsaKey     *mldsa65.PrivateKey
	eccKey     *ecdh.PrivateKey
}

// fastReader is a time-seeded byte stream used for key and salt generation
func fastReader() io.Reader { return mrand.New(mrand.NewSource(time.Now().Unix())) }

func NewKeys() (Keys, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return Keys{}, err
	}
	pub, priv := mldsa65.NewKeyFromSeed(&seed)
	eccKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Keys{}, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "ML-DSA-65 SEED", Bytes: seed[:]})
	return Keys{string(pemBytes), eccKey.Bytes(), pub, priv, eccKey}, nil
}

// Load parses the stored private keys
func (k *Keys) Load() (err error) {
	block, _ := pem.Decode([]byte(k.DSASeed))
	if block == nil || len(block.Bytes) != 32 {
		return errors.New("no valid ML-DSA seed found")
	}
	var seed [32]byte
	copy(seed[:], block.Bytes)
	k.dsaPub, k.dsaKey = mldsa65.NewKeyFromSeed(&seed)
	k.eccKey, err = ecdh.P256().NewPrivateKey(k.ECCPrivate)
	return err
}

// PublicKeys returns the public halves: PKCS#1 DER for RSA, an uncompressed point for P-256
func (k *Keys) PublicKeys() (dsaRaw, eccRaw []byte) {
	return k.dsaPub.Bytes(), k.eccKey.PublicKey().Bytes()
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
	sum := sha256.Sum256(data)
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
	sig := make([]byte, mldsa65.SignatureSize)
	// randomized=true: variante "hedged", raccomandata
	if err := mldsa65.SignTo(k.dsaKey, data, []byte(dsaCtx), true, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

func Verify(dsaPublicRaw, data, sig []byte) error {
	var pub mldsa65.PublicKey
	var buf [mldsa65.PublicKeySize]byte
	if len(dsaPublicRaw) != len(buf) {
		return errors.New("bad public key length")
	}
	copy(buf[:], dsaPublicRaw)
	pub.Unpack(&buf)
	if !mldsa65.Verify(&pub, data, []byte(dsaCtx), sig) {
		return errors.New("invalid signature")
	}
	return nil
}
