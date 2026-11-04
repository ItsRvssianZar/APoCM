package internal

import (
	"crypto/rand"
	"errors"

	"ml-dsa/internal/field"
	"ml-dsa/internal/params"
	"ml-dsa/internal/ring"
	"ml-dsa/internal/util"
)

// Algorithm 7
//
// The message representative being signed is:
// Mprime
//
// Additional randomness is passed as:
// rnd
//
// Returns a signature as a []byte
// א
func (sk *SigningKey) SignInternal(Mprime, rnd []byte) []byte {
	cfg := sk.cfg
	s1hat := util.NttVec(sk.s1)
	s2hat := util.NttVec(sk.s2)
	t0hat := util.NttVec(sk.t0)
	Ahat := util.ExpandA(sk.cfg, sk.rho[:])

	// mu <- H(BytesToBits(tr) || M', 64)
	mu := make([]byte, 64)
	util.H(mu, append(sk.tr[:], Mprime...))

	// rhopp <- H(K || rnd || mu, 64)
	rhopp := make([]byte, 64)
	tmp := append(sk.K[:], rnd...)
	tmp = append(tmp, mu...)
	util.H(rhopp, tmp)

	// Public rejection bounds.
	gamma1_beta := (uint32(1) << cfg.LogGamma1) - uint32(cfg.Beta)
	gamma2_beta := cfg.Gamma2 - uint32(cfg.Beta)

	// Rejection sampling loop.
	for kappa := uint16(0); ; kappa += uint16(cfg.L) {
		y := ring.FromSymmetricVec(util.ExpandMask(cfg, rhopp, kappa))
		w := util.InvNttVec(util.MatrixVectorNTT(Ahat, util.NttVec(y)))
		w1_encoded := util.W1Encode(cfg, ring.HighBitsVec(w, cfg.Gamma2))

		c_tilde := make([]byte, cfg.Lambda>>4)
		util.H(c_tilde, append(mu, w1_encoded...))
		c := util.SampleInBall(cfg, c_tilde)
		c_hat := util.NTT(ring.FromSymmetric(c))

		cs1 := util.InvNttVec(util.ScalarVectorNTT(c_hat, s1hat))
		cs2 := util.InvNttVec(util.ScalarVectorNTT(c_hat, s2hat))
		z := util.AddVector(y, cs1)
		r0 := ring.LowBitsVec(util.SubVector(w, cs2), cfg.Gamma2)

		z_inf := ring.InfinityNormVec(z)
		r0_inf := ring.InfinityNormVec(ring.FromSymmetricVec(r0))

		// Each flag is 1 if the corresponding norm >= bound.
		reject := uint32(1) ^ uint32(
			(uint64(z_inf)-uint64(gamma1_beta))>>63,
		)
		reject |= uint32(1) ^ uint32(
			(uint64(r0_inf)-uint64(gamma2_beta))>>63,
		)

		// Compute ct0 and the hint on every attempt.
		ct0 := util.InvNttVec(util.ScalarVectorNTT(c_hat, t0hat))
		minus_ct0 := util.NegateVector(ct0)
		w_cs2_ct0 := util.AddVector(util.SubVector(w, cs2), ct0)
		ct0_inf := ring.InfinityNormVec(ct0)

		// Returns nil if the hint's Hamming weight is too large.
		h := util.MakeHint(cfg, minus_ct0, w_cs2_ct0)

		reject |= uint32(1) ^ uint32(
			(uint64(ct0_inf)-uint64(cfg.Gamma2))>>63,
		)

		if h == nil || reject != 0 {
			continue
		}

		return util.SigEncode(cfg, c_tilde, z, h)
	}
}

// Sign takes a message and a context and returns a signature.
// Only pure ML-DSA is supported.
func (sk *SigningKey) Sign(message []byte) ([]byte, error) {
	rnd := make([]byte, 32)
	rng := rand.Reader
	n, err := rng.Read(rnd)
	if err != nil {
		return nil, err
	}
	if n != len(rnd) {
		return nil, errors.New("rng.Read() returned too few bytes")
	}

	Mprime := make([]byte, 0, len(message)+2)
	Mprime = append(Mprime, byte(0), byte(0))
	Mprime = append(Mprime, message...)

	sigma := sk.SignInternal(Mprime, rnd)
	return sigma, nil
}

// Algorithm 8
//
// The message representitve for the signature is:
// Mprime
//
// The signature being validated is:
// sigma
//
// Returns true if the signature is valid.
// Returns false otherwise (even if an error occurs).
// א
func (pk *VerifyingKey) VerifyInternal(Mprime, sigma []byte) bool {
	cfg := pk.cfg
	c_tilde, z, h, err := util.SigDecode(cfg, sigma)
	if err != nil {
		return false
	}

	// Check the decoded challenge length before indexing it.
	if len(c_tilde) != int(cfg.Lambda>>2) {
		return false
	}

	Azhat := util.MatrixVectorNTT(
		util.ExpandA(cfg, pk.rho[:]),
		util.NttVec(ring.FromSymmetricVec(z)),
	)

	tr := make([]byte, 64)
	util.H(tr, pk.Bytes())

	mu := make([]byte, 64)
	util.H(mu, append(tr, Mprime...))

	c := util.SampleInBall(cfg, c_tilde)
	c_hat := util.NTT(ring.FromSymmetric(c))

	t1_2d := util.ScalarVector(
		field.NewFromReduced(1<<params.D),
		pk.t1,
	)

	t1_2d_hat := util.NttVec(t1_2d)
	ct1_2d_hat := util.ScalarVectorNTT(c_hat, t1_2d_hat)
	w_approx := util.InvNttVec(
		util.SubVectorNTT(Azhat, ct1_2d_hat),
	)

	w1_encoded := util.W1Encode(
		cfg,
		util.UseHint(cfg, h, w_approx),
	)

	c_tilde_prime := make([]byte, cfg.Lambda>>2)
	util.H(c_tilde_prime, append(mu, w1_encoded...))

	z_inf := ring.InfinityNormVec(ring.FromSymmetricVec(z))
	bound := (uint32(1) << cfg.LogGamma1) - uint32(cfg.Beta)

	// 1 if z_inf >= bound, 0 otherwise.
	reject := uint32(1) ^ uint32(
		(uint64(z_inf)-uint64(bound))>>63,
	)

	// Examine every byte, without returning at the first mismatch.
	for i := range c_tilde {
		reject |= uint32(c_tilde[i] ^ c_tilde_prime[i])
	}

	return reject == 0
}

// Verify verifies a signature.
//
// Only pure ML-DSA is supported.
func (pk *VerifyingKey) Verify(msg, sig []byte) bool {
	Mprime := make([]byte, 0, len(msg)+2)
	Mprime = append(Mprime, byte(0), byte(0))
	Mprime = append(Mprime, msg...)

	return pk.VerifyInternal(Mprime, sig)
}
