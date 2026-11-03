package mldsa44

import (
	"crypto"

	internal "ml-dsa/internal"
	"ml-dsa/internal/params"
)

type PublicKey struct {
	pk internal.VerifyingKey
}

type PrivateKey struct {
	sk internal.SigningKey
}

func GenerateKeyPair() (*PublicKey, *PrivateKey, error) {
	sk, pk, err := internal.GenerateKeyPair(params.MLDSA44Cfg)

	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{*pk}, &PrivateKey{*sk}, nil
}

func (pub *PublicKey) Verify(msg, sig []byte) bool {
	return pub.pk.Verify(msg, sig)
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return priv.sk.Public()
}

func (pub *PublicKey) Bytes() []byte {
	return pub.pk.Bytes()
}

func PublicKeyFromBytes(bytes []byte) (*PublicKey, error) {
	pk, err := internal.PkDecode(params.MLDSA44Cfg, bytes)
	if err != nil {
		return nil, err
	}
	return &PublicKey{*pk}, nil
}

func (priv *PrivateKey) Sign(message []byte) ([]byte, error) {
	return priv.sk.Sign(message)
}

func (priv *PrivateKey) Seed() ([]byte, error) {
	return priv.sk.Bytes()
}

func PrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	sk, err := internal.FromSeed(params.MLDSA44Cfg, seed)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{*sk}, nil
}
