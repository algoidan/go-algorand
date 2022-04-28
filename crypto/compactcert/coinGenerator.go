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
	"encoding/binary"
	"golang.org/x/crypto/sha3"
	"math/big"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// The coinChoiceSeed defines the randomness seed that will be given to an XOF function. This will be used for choosing
// the index of the coin to reveal as part of the compact certificate.
type coinChoiceSeed struct {
	// the ToBeHashed function should be updated when fields are added to this structure

	partCommitment crypto.GenericDigest
	lnProvenWeight uint64
	sigCommitment  crypto.GenericDigest
	signedWeight   uint64
	data           StateProofMessageHash
}

// ToBeHashed returns a binary representation of the coinChoiceSeed structure.
// Since this code is also implemented as a circuit in the stateproof SNARK prover we can't use
// msgpack encoding since it may result in a variable length byte slice.
// Alternatively, we serialize the fields in the structure in a specific format.
func (cc *coinChoiceSeed) ToBeHashed() (protocol.HashID, []byte) {
	signedWtAsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(signedWtAsBytes, cc.signedWeight)

	lnProvenWtAsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lnProvenWtAsBytes, cc.lnProvenWeight)

	coinChoiceBytes := make([]byte, 0, len(cc.partCommitment)+len(lnProvenWtAsBytes)+len(cc.sigCommitment)+len(signedWtAsBytes)+len(cc.data))
	coinChoiceBytes = append(coinChoiceBytes, cc.partCommitment...)
	coinChoiceBytes = append(coinChoiceBytes, lnProvenWtAsBytes...)
	coinChoiceBytes = append(coinChoiceBytes, cc.sigCommitment...)
	coinChoiceBytes = append(coinChoiceBytes, signedWtAsBytes...)
	coinChoiceBytes = append(coinChoiceBytes, cc.data[:]...)

	return protocol.CompactCertCoin, coinChoiceBytes
}

// coinGenerator is used for extracting "randomized" 64 bits for coin flips
type coinGenerator struct {
	shkContext   sha3.ShakeHash
	signedWeight *big.Int
	threshold    *big.Int
}

// makeCoinGenerator creates a new CoinHash context.
// it is used for squeezing 64 bits for coin flips.
// the function inits the XOF function in the following manner
// Shake(coinChoiceSeed)
// we extract 64 bits from shake for each coin flip and divide it by signedWeight
func makeCoinGenerator(choice *coinChoiceSeed) coinGenerator {
	rep := crypto.HashRep(choice)
	shk := sha3.NewShake256()
	shk.Write(rep)

	threshold, signedWt := prepareRejectionSamplingValues(choice.signedWeight)
	return coinGenerator{shkContext: shk, signedWeight: signedWt, threshold: threshold}

}

func prepareRejectionSamplingValues(signedWeight uint64) (*big.Int, *big.Int) {
	// we use rejection sampling in order to have a uniform random coin in [0,signedWeight).
	// use b bits (b=64) per attempt.
	// define k = roundDown( 2^b / signedWeight )  implemented as (2^b div signedWeight)
	// and threshold = k*signedWeight
	threshold := &big.Int{}
	threshold.SetUint64(1)

	const numberOfBitsPerAttempt = 64
	threshold.Lsh(threshold, numberOfBitsPerAttempt)

	signedWt := &big.Int{}
	signedWt.SetUint64(signedWeight)

	// k = 2^b / signedWeight
	threshold.Div(threshold, signedWt)

	threshold.Mul(threshold, signedWt)
	return threshold, signedWt
}

// getNextCoin returns the next 64bits integer which represents a number between [0,signedWeight)
func (cg *coinGenerator) getNextCoin() uint64 {
	// take b bits from the XOF and generate an integer z.
	// we accept the sample if z < threshold
	// else, we reject the sample and repeat the process.
	z := &big.Int{}
	for true {
		var shakeDigest [8]byte
		cg.shkContext.Read(shakeDigest[:])
		randNumFromXof := binary.LittleEndian.Uint64(shakeDigest[:])

		z.SetUint64(randNumFromXof)
		if comp := z.Cmp(cg.threshold); comp == -1 {
			break
		}
	}

	z.Mod(z, cg.signedWeight)
	return z.Uint64()
}
