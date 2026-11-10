package main

import (
	"bytes"
	"crypto/aes"
	"crypto/mlkem"
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

// Keys contains a user's key material
type Keys struct {
	DSASeed   string // PEM, contiene il seed da 32 byte
	MLKEMSeed string
	dsaPub    *mldsa65.PublicKey
	dsaKey    *mldsa65.PrivateKey
	mlkemKey  *mlkem.DecapsulationKey1024
}

// fastReader is a time-seeded byte stream used for key and salt generation
func fastReader() io.Reader { return mrand.New(mrand.NewSource(time.Now().Unix())) }

func NewKeys() (Keys, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return Keys{}, err
	}
	pub, priv := mldsa65.NewKeyFromSeed(&seed)
	var mlkemseed [64]byte
	if _, err := rand.Read(mlkemseed[:]); err != nil {
		return Keys{}, err
	}
	mlkempriv, err := mlkem.NewDecapsulationKey1024(mlkemseed[:])
	if err != nil {
		return Keys{}, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "ML-DSA-65 SEED", Bytes: seed[:]})
	seedPem := pem.EncodeToMemory(&pem.Block{Type: "MLKEM SEED", Bytes: mlkemseed[:]})
	return Keys{string(pemBytes), string(seedPem), pub, priv, mlkempriv}, nil
}

// Load parses the stored private keys
func (k *Keys) Load() (err error) {
	block, _ := pem.Decode([]byte(k.DSASeed))
	if block == nil || len(block.Bytes) != 32 {
		return errors.New("no valid ML-DSA seed found")
	}
	k.dsaPub, k.dsaKey = mldsa65.NewKeyFromSeed((*[32]byte)(block.Bytes))
	block2, _ := pem.Decode([]byte(k.MLKEMSeed))
	if block2 == nil || len(block2.Bytes) != 64 {
		return errors.New("no valid MLKEM seed found")
	}
	k.mlkemKey, err = mlkem.NewDecapsulationKey1024(block2.Bytes)
	return err
}

// PublicKeys returns the public halves: PKCS#1 DER for RSA, an uncompressed point for P-256
func (k *Keys) PublicKeys() (dsaRaw, mlkemRaw []byte) {
	return k.dsaPub.Bytes(), k.mlkemKey.EncapsulationKey().Bytes()
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

// WrapKey encrypts a file key for the owner of recipientECC; ephemeral must travel with it
func WrapKey(recipientKEM, fileKey []byte) (kemCiphertext, wrapped []byte, err error) {
	pub, err := mlkem.NewEncapsulationKey1024(recipientKEM)
	if err != nil {
		return nil, nil, err
	}
	shared, kemCiphertext := pub.Encapsulate()
	kek := sha256.Sum256(shared)
	wrapped, err = Encrypt(kek[:], fileKey)
	if err != nil {
		return nil, nil, err
	}
	return kemCiphertext, wrapped, nil
}

func (k *Keys) UnwrapKey(kemC, wrapped []byte) ([]byte, error) {
	shared, err := k.mlkemKey.Decapsulate(kemC)
	if err != nil {
		return nil, err
	}
	kek := sha256.Sum256(shared)
	key, err := Decrypt(kek[:], wrapped)
	if err != nil {
		return nil, err
	}
	if len(key) != keyLen {
		return nil, errors.New("unexpected key length")
	}
	return key, nil
}

func (k *Keys) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(k.dsaKey, digest[:], nil, true, sig); err != nil {
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
	digest := sha256.Sum256(data)
	if !mldsa65.Verify(&pub, digest[:], nil, sig) {
		return errors.New("invalid signature")
	}
	return nil
}
