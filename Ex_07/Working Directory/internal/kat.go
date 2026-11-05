package internal

import (
	"ml-dsa/internal/params"
	"ml-dsa/internal/util"
)

type KATState struct {
	Seed []byte

	Rho []byte
	K   []byte
	Tr  []byte

	S1 []byte
	S2 []byte
	T0 []byte
	T1 []byte
}

// Export all internal values needed for FIPS-204 KAT checking
func (sk *SigningKey) KAT() *KATState {

	res := &KATState{
		Seed: append([]byte(nil), sk.seed...),

		Rho: append([]byte(nil), sk.rho[:]...),
		K:   append([]byte(nil), sk.K[:]...),
		Tr:  append([]byte(nil), sk.tr[:]...),
	}

	// s1
	for i := range sk.cfg.L {
		packed := util.BitPackClosed(
			sk.s1[i].Symmetric(),
			sk.cfg.LogEta,
		)
		res.S1 = append(res.S1, packed[:]...)
	}

	// s2
	for i := range sk.cfg.K {
		packed := util.BitPackClosed(
			sk.s2[i].Symmetric(),
			sk.cfg.LogEta,
		)
		res.S2 = append(res.S2, packed[:]...)
	}

	// t0
	for i := range sk.cfg.K {
		packed := util.BitPack(
			sk.t0[i].Symmetric(),
			params.D-1,
		)
		res.T0 = append(res.T0, packed[:]...)
	}

	// t1 (public key part)
	for i := range sk.cfg.K {
		packed := util.SimpleBitPack(
			sk.t1[i].Symmetric(),
			10,
		)
		res.T1 = append(res.T1, packed[:]...)
	}

	return res
}
