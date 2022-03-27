// Copyright (C) 2019-2022 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package compactcert

import (
	"errors"
	"fmt"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"math"
	"math/big"
	"math/bits"
)

// Errors for the CompactCert verifier
var (
	ErrCoinNotInRange                   = errors.New("coin is not within slot weight range")
	ErrNoRevealInPos                    = errors.New("no reveal for position")
	ErrSignedWeightLessThanProvenWeight = errors.New("signed weight is less than or equal to proven weight")
	ErrTooManyReveals                   = errors.New("too many reveals in cert")
	ErrZeroSignedWeight                 = errors.New("signed weight can not be zero")
	ErrInsufficientImpliedProvenWeight  = errors.New("signed weight and number of reveals yield insufficient proven weight")
)

// Verifier is used to verify a compact certificate.
type Verifier struct {
	Params

	lnProvenWeightThresholdAsInteger uint64 // ln(provenWeightThreshold) with 16 bits of precision
	partcom                          crypto.GenericDigest
}

// MkVerifier constructs a verifier to check the compact certificate
// on the message specified in p, with partcom specifying the Merkle
// root of the participants that must sign the message.
func MkVerifier(p Params, partcom crypto.GenericDigest) *Verifier {
	provenWt := lnWithPrecision(p.ProvenWeightThreshold, precisionBits)
	return &Verifier{
		Params:                           p,
		lnProvenWeightThresholdAsInteger: provenWt,
		partcom:                          partcom,
	}
}

func (v *Verifier) verifyWeights(signedWeight uint64, numOfReveals uint64) error {
	if numOfReveals > MaxReveals {
		return ErrTooManyReveals
	}

	if signedWeight == 0 {
		return ErrZeroSignedWeight
	}

	if signedWeight <= v.ProvenWeightThreshold {
		return fmt.Errorf("%w - signed weight %d <= proven weight %d", ErrSignedWeightLessThanProvenWeight, signedWeight, v.ProvenWeightThreshold)
	}

	// find d s.t 2^(d+1) >= signedWeight >= 2^(d)
	d := uint64(bits.Len64(signedWeight)) - 1

	signedWtPower2 := &big.Int{}
	signedWtPower2.SetUint64(signedWeight)
	signedWtPower2.Mul(signedWtPower2, signedWtPower2)

	// Y = signedWt^2 + 4*2^d*signedWt +2^2d
	// 		   tmp = 4*2^d*signedWt
	tmp := &big.Int{}
	tmp.SetUint64(4)
	tmp.Mul(tmp, (&big.Int{}).SetUint64(1<<d))
	tmp.Mul(tmp, (&big.Int{}).SetUint64(signedWeight))

	y := &big.Int{}
	y.Add(signedWtPower2, tmp)
	y.Add(y, (&big.Int{}).SetUint64(1<<(2*d)))

	// a = 3*2^b*(signedWt^2-2^2d) + d*(T-1)*Y
	// 			tmp = d*(T-1)*Y
	tmp.SetUint64(d)
	tmp.Mul(tmp, (&big.Int{}).SetUint64(ln2AsInteger-1))
	tmp.Mul(tmp, y)

	a := &big.Int{}
	a.Sub(signedWtPower2, (&big.Int{}).SetUint64(1<<(2*d)))
	a.Mul(a, (&big.Int{}).SetUint64(3))
	a.Mul(a, (&big.Int{}).SetUint64(precisionBits))
	a.Add(a, tmp)

	// left = NumReveals*a
	left := &big.Int{}
	left.Mul(a, (&big.Int{}).SetUint64(numOfReveals))

	// right = (secParam*t + NumReveals*P)*Y
	//			tmp = secParam*t
	tmp.SetUint64(v.SecKQ)
	tmp.Mul(tmp, (&big.Int{}).SetUint64(ln2AsInteger))

	right := &big.Int{}
	right.Mul((&big.Int{}).SetUint64(v.lnProvenWeightThresholdAsInteger), (&big.Int{}).SetUint64(numOfReveals))
	right.Add(tmp, right)
	right.Mul(right, y)

	if left.Cmp(right) < 0 {
		return ErrInsufficientImpliedProvenWeight
	}

	return nil
}

func lnWithPrecision(x uint64, precisionBits uint64) uint64 {
	result := math.Log(float64(x))
	expendWithPer := result * float64(precisionBits)
	return uint64(math.Ceil(expendWithPer))
}

// Verify checks if c is a valid compact certificate for the message
// and participants that were used to construct the Verifier.
func (v *Verifier) Verify(c *Cert) error {
	nr := uint64(len(c.PositionsToReveal))
	if err := v.verifyWeights(c.SignedWeight, nr); err != nil {
		return err
	}

	version := int(c.MerkleSignatureVersion)
	for _, reveal := range c.Reveals {
		if err := reveal.SigSlot.Sig.ValidateSigVersion(version); err != nil {
			return err
		}
	}

	sigs := make(map[uint64]crypto.Hashable)
	parts := make(map[uint64]crypto.Hashable)

	msghash := v.Params.StateProofMessageHash
	for pos, r := range c.Reveals {
		sig, err := buildCommittableSignature(r.SigSlot)
		if err != nil {
			return err
		}

		sigs[pos] = sig
		parts[pos] = r.Part

		// verify that the msg and the signature is valid under the given participant's Pk
		err = r.Part.PK.VerifyBytes(
			uint64(v.SigRound),
			msghash[:],
			r.SigSlot.Sig,
		)

		if err != nil {
			return fmt.Errorf("signature in reveal pos %d does not verify. error is %w", pos, err)
		}
	}

	// verify all the reveals proofs on the signature tree.
	if err := merklearray.VerifyVectorCommitment(c.SigCommit[:], sigs, &c.SigProofs); err != nil {
		return err
	}

	// verify all the reveals proofs on the participant tree.
	if err := merklearray.VerifyVectorCommitment(v.partcom[:], parts, &c.PartProofs); err != nil {
		return err
	}

	choice := coinChoiceSeed{
		SignedWeight: c.SignedWeight,
		Sigcom:       c.SigCommit,
		Partcom:      v.partcom,
		MsgHash:      v.StateProofMessageHash,
	}

	coinHash := makeCoinGenerator(choice)
	for j := uint64(0); j < nr; j++ {
		pos := c.PositionsToReveal[j]
		reveal, exists := c.Reveals[pos]
		if !exists {
			return fmt.Errorf("%w: %d", ErrNoRevealInPos, pos)
		}

		coin := coinHash.getNextCoin()
		if !(reveal.SigSlot.L <= coin && coin < reveal.SigSlot.L+reveal.Part.Weight) {
			return fmt.Errorf("%w: for reveal pos %d and coin %d, ", ErrCoinNotInRange, pos, coin)
		}
	}

	return nil
}
