package params

const Q = 8380417
const N = 256
const Zeta = 1753
const D = 13

type Cfg struct {
	Name      string
	Tau       uint16
	Lambda    uint16
	LogGamma1 uint8
	Gamma2    uint32
	K         uint8
	L         uint8
	LogEta    uint8
	Beta      uint8
	Omega     uint8
	W1Bits    uint8  // Bit length of entries in W1 = bitlen((q-1)/(2*Gamma2) - 1)
	SkSize    uint16 // Byte size of expanded secret key - only used for known answer testing
	PkSize    uint16 // Byte size of encoded public key
	SigSize   uint16 // Byte size of encoded signature
}

var MLDSA44Cfg = &Cfg{
	Name:      "MLDSA-44",
	Tau:       39,
	Lambda:    128,
	LogGamma1: 17,
	Gamma2:    (Q - 1) / 88,
	K:         4,
	L:         4,
	LogEta:    1,
	Beta:      78,
	Omega:     80,
	W1Bits:    6, // bitlen(43)
	SkSize:    2560,
	PkSize:    1312,
	SigSize:   2420,
}
