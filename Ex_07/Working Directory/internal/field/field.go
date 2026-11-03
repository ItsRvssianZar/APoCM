package field

import (
	"crypto/subtle"
	"math/bits"

	"ml-dsa/internal/params"
)

// T is the type of field elements F_q, where q = 8380417.
type T struct {
	reduced uint32 // TODO: implement Montgomery representation
}

const (
	q                 = params.Q
	d                 = params.D
	barrettMultiplier = 8396807 // 2²³ * 2²³ / q
	barrettShift      = 46      // log₂(2²³ * 2²³)
)

// NewFromReduced creates a new field element from a reduced non-negative value.
func NewFromReduced(reduced uint32) T {
	return T{reduced: reduced}
}

// NewFromSymmetric creates a new field element from a reduced signed value.
func NewFromSymmetric(x int32) T {
	y := uint32(x) + (uint32(x)>>31)*q
	return NewFromReduced(y)
}

// Reduce a field element once, mod q.
func reduceOnce(a uint32) T {
	x := uint32(a - q)
	x += (x >> 31) * q
	return NewFromReduced(x)
}

// Add two field elements, mod q.
func (a T) Add(b T) T {
	return reduceOnce(a.reduced + b.reduced)
}

// Subtract two field elements, mod q.
func (a T) Sub(b T) T {
	return reduceOnce(a.reduced - b.reduced + q)
}

// Negate a field element, mod q.
func (a T) Neg() T {
	return reduceOnce(q - a.reduced)
}

// Multiply two field elements, mod q.
func (a T) Mul(b T) T {
	// Constant-time Barrett reduction for 64-bit product modulo q
	// q fits in 32 bits. Let mu = floor(2^64 / q).
	// For x < q^2, r = x - floor((x * mu) / 2^64) * q gives r < 2q.
	// Apply two branchless correction steps to ensure r < q.
	const q64 = uint64(q)
	const mu uint64 = 2201172575745 // floor(2^64 / 8380417)

	x := uint64(a.reduced) * uint64(b.reduced)
	hi, _ := bits.Mul64(x, mu)
	r := x - hi*q64

	// First correction: if r >= q then r -= q (branchless)
	r1, borrow := bits.Sub64(r, q64, 0)
	correction := borrow ^ 1 // 1 if r >= q, 0 otherwise
	mask := uint64(0) - uint64(correction)
	r ^= mask & (r ^ r1)

	// Second correction (safe even if not needed)
	r2, borrow2 := bits.Sub64(r, q64, 0)
	correction2 := borrow2 ^ 1
	mask2 := uint64(0) - uint64(correction2)
	r ^= mask2 & (r ^ r2)

	return T{uint32(r)}
}

// Power2Round (Algorithm 35) decomposes a field element x into two components:
// (r1, r0) such that x = r1 * 2^d + r0 (mod q)
// and r0 \in (-2^(d-1), 2^(d-1)].
// r1 is then in the range [0, q/2^d), which is 10 bits
// א
func (a T) Power2Round() (int32, int32) {
	r0 := int32(a.reduced) & ((1 << d) - 1)

	mask := (int32(1<<(d-1)) - r0) >> 31
	r0 -= (int32(1) << d) & mask

	r1 := (int32(a.reduced) - r0) >> d
	return r1, r0
}

// Decompose (Algorithm 36) decomposes a field element x into two components:
// (r1, r0) such that x = r1 * (2 * gamma2) + r0 (mod q)
// -gamma2 < r0 <= gamma2
// 0 <= r1 < (q-1)/(2 * gamma2)
// א
func (a T) Decompose(gamma2 uint32) (r1 int32, r0 int32) {

	r := int32(a.Reduced())
	twoGamma2 := int32(gamma2 << 1)
	gamma2Int := int32(gamma2)

	// r += q & (r >> 31)

	// Center r around 0 (map to range [-(q-1)/2, (q-1)/2])
	mask := (-r + (q-1)/2) >> 31
	r -= (q - 1) & mask

	// Compute r1 = round(r/alpha) with ties broken towards zero
	// For r >= 0: r1 = (r + gamma2Int) / twoGamma2
	// For r < 0:  r1 = (r - gamma2Int + 1) / twoGamma2
	signMask := r >> 31
	offset := gamma2Int + (signMask & (-twoGamma2 + 1))
	r1 = (r + offset) / twoGamma2

	// Compute r0 = r - r1*twoGamma2
	r0 = r - r1*twoGamma2

	// Adjust r1 if r0 is too large (branch-free)
	// If r0 > gamma2Int: r1++, r0 -= twoGamma2
	// If r0 < -gamma2Int: r1--, r0 += twoGamma2

	// Check if r0 > alpha/2
	adjustUp := ((-r0 + gamma2Int) >> 31)
	r1 += adjustUp & 1
	r0 -= adjustUp & twoGamma2

	// Check if r0 < -gamma2Int
	adjustDown := ((r0 + gamma2Int) >> 31)
	r1 -= adjustDown & 1
	r0 += adjustDown & twoGamma2

	return r1, r0
}

// Algorithm 37
func (a T) HighBits(gamma2 uint32) int32 {
	r1, _ := a.Decompose(gamma2)
	return r1
}

// InfinityNorm computes the absolute value of the
// signed symmetric representation of a field element.
func (a T) InfinityNorm() uint32 {
	return min(a.reduced, q-a.reduced)
}

// Reduced returns the [0, q-1] representative
func (a T) Reduced() uint32 {
	return a.reduced
}

// Symmetric returns the [-q/2, q/2]
func (a T) Symmetric() int32 {
	mask := subtle.ConstantTimeLessOrEq(q>>1+1, int(a.reduced))
	return int32(a.reduced) - (int32(mask) * int32(q))
}

// Algorithm 15
// Input: eta, byte
// Output: integer between -eta and eta or nil for rejection
func FromHalfByte(eta int, b byte) *T {
	var r T
	if eta == 2 && b < 15 {
		r = NewFromSymmetric(2 - (int32(b) % 5))
		return &r
	}
	if eta == 4 && b < 9 {
		r = NewFromSymmetric(4 - int32(b))
		return &r
	}
	return nil
}

// Algorithm 14
// Inputs: 3 bytes
// Output: integer mod q or nil for rejection
// א
func FromThreeBytes(b0, b1, b2 byte) *T {
	var r T
	bp2 := uint32(b2 & 0x7f)
	z := (bp2 << 16) | uint32(b1)<<8 | uint32(b0)

	// if q <= z, return an error
	invalid := (q - (z + 1)) >> 31
	if invalid != 0 {
		return nil
	}
	r = NewFromReduced(z)
	return &r
}

// Alternate to integer division by using Barrett Reduction
// Calculates (n/d, n%d) given (n, d)
func DivBarrett(numerator, denominator uint32) (uint32, uint32) {
	// Since d is always 2 * gamma2, we can precompute (2^64 / d) and use it
	var reciprocal uint64
	switch denominator {
	case 95232:
		reciprocal = 193703209779376
	case 261888:
		reciprocal = 70368744177664
	case 190464:
		reciprocal = 96851604889688
	case 523776:
		reciprocal = 35184372088832
	default:
		// Fallback to slow division
		return DivConstTime32(numerator, denominator)
	}

	// Barrett reduction
	hi, _ := bits.Mul64(uint64(numerator), reciprocal)
	quo := uint32(hi)
	r := numerator - quo*denominator

	// Two correction steps using bits.Sub32 (constant-time)
	for i := 0; i < 2; i++ {
		newR, borrow := bits.Sub32(r, denominator, 0)
		correction := borrow ^ 1 // 1 if r >= d, 0 if r < d
		mask := uint32(-correction)
		quo += mask & 1
		r ^= mask & (newR ^ r) // Conditional swap using XOR
	}

	return quo, r
}

// For signed integers:
func divBarrettSigned(numerator, denominator int32) (int32, int32) {
	un := uint32(numerator)
	ud := uint32(denominator)
	quo, r := DivBarrett(un, ud)
	return int32(quo), int32(r)
}

// Modification of https://en.wikipedia.org/wiki/Division_algorithm#Integer_division_(unsigned)_with_remainder
// Except with branchless, conditional swaps
//
// This function works for arbitrary values for d, but is slower than DivBarrett.
func DivConstTime32(n uint32, d uint32) (uint32, uint32) {
	quotient := uint32(0)
	R := uint32(0)

	// We are dealing with 32-bit integers, so we iterate 32 times
	b := uint32(32)
	i := b
	for range b {
		i--
		R <<= 1

		// R(0) := N(i)
		R |= ((n >> i) & 1)

		// swap from Sub32() will look like this:
		// if remainder > d,  swap == 0
		// if remainder == d, swap == 0
		// if remainder < d,  swap == 1
		Rprime, swap := bits.Sub32(R, d, 0)

		// invert logic of sub32 for conditional swap
		swap ^= 1
		/*
			Desired:
				if R > D  then swap = 1
				if R == D then swap = 1
				if R < D  then swap = 0
		*/

		// Qprime := Q
		// Qprime(i) := 1
		Qprime := quotient
		Qprime |= (1 << i)

		// Conditional swap:
		mask := uint32(-swap)
		R ^= ((Rprime ^ R) & mask)
		quotient ^= ((Qprime ^ quotient) & mask)
	}
	return quotient, R
}
