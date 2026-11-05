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

/*
Same for all category:

Seed: z_2.txt, z_3.txt, z_5.txt
Message length: mlen_2.txt, mlen_3.txt, mlen_5.txt
Message : m_2.txt, m_3.txt, m_5.txt
Key Genertion:

s1: s1_2.txt, s1_3.txt, s1_5.txt
s2: s2_2.txt, s2_3.txt, s2_5.txt
t0: t0_2.txt, t0_3.txt, t0_5.txt
t1: t1_2.txt, t1_3.txt, t1_5.txt
K: k_2.txt, k_3.txt, k_5.txt
rho: rho_2.txt, rho_3.txt, rho_5.txt
tr: tr_2.txt, tr_3.txt, tr_5.txt
Signature Generation

signature z: zs_2.txt, zs_3.txt, zs_5.txt
hint: h_2.txt, h_3.txt, h_5.txt
challenge: c_2.txt, c_3.txt, c_5.txt
*/
