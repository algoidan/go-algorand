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

package verify

import (
	"errors"
	"fmt"
	"github.com/algorand/go-algorand/ledger/ledgercore"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errStateProofCrypto     = errors.New("state proof crypto error")
	errStateProofNotEnabled = errors.New("state proofs are not enabled")
	errNotAtRightMultiple   = errors.New("state proof is not in a valid round multiple")
	errInsufficientWeight   = errors.New("insufficient state proof weight")
)

// AcceptableStateProofWeight computes the acceptable signed weight
// of a state proof if it were to appear in a transaction with a
// particular firstValid round.  Earlier rounds require a smaller proof.
// votersHdr specifies the block that contains the vector commitment of
// the voters for this state proof (and thus the state proof is for the interval
// (votersHdr.Round(), votersHdr.Round()+StateProofInterval].
//
// logger must not be nil; use at least logging.Base()
func AcceptableStateProofWeight(votersHdr *bookkeeping.BlockHeader, firstValid basics.Round, logger logging.Logger) uint64 {
	proto := config.Consensus[votersHdr.CurrentProtocol]
	latestRoundInProof := votersHdr.Round + basics.Round(proto.StateProofInterval)
	total := votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight

	return calculateAcceptableStateProofWeight(total, proto.StateProofInterval, proto.StateProofWeightThreshold, latestRoundInProof, firstValid, logger)
}

func calculateAcceptableStateProofWeight(totalOnline basics.MicroAlgos, stateProofInterval uint64, provenWeightThreshold uint32, lastAttestedRound basics.Round, firstValid basics.Round, logger logging.Logger) uint64 {

	halfPeriodForInterval := stateProofInterval / 2
	// The acceptable weight depends on the elapsed time (in rounds)
	// from the block we are trying to construct a proof for.
	// Start by subtracting the latest round number in the state proof interval.
	// If that round hasn't even passed yet, require 100% votes in proof.
	offset := firstValid.SubSaturate(lastAttestedRound)
	if offset == 0 {
		return totalOnline.ToUint64()
	}

	// During the first proto.StateProofInterval/2 blocks, the
	// signatures are still being broadcast, so, continue requiring
	// 100% votes.
	offset = offset.SubSaturate(basics.Round(halfPeriodForInterval))
	if offset == 0 {
		return totalOnline.ToUint64()
	}

	// In the next proto.StateProofInterval/2 blocks, linearly scale
	// the acceptable weight from 100% to StateProofWeightThreshold.
	// If we are outside of that window, accept any weight at or above
	// StateProofWeightThreshold.
	provenWeight, overflowed := basics.Muldiv(totalOnline.ToUint64(), uint64(provenWeightThreshold), 1<<32)
	if overflowed || provenWeight > totalOnline.ToUint64() {
		// Shouldn't happen, but a safe fallback is to accept a larger proof.
		logger.Warnf("calculateAcceptableStateProofWeight(%d, %d, %d, %d) overflow provenWeight",
			totalOnline, stateProofInterval, lastAttestedRound, firstValid)
		return 0
	}

	if offset >= basics.Round(halfPeriodForInterval) {
		return provenWeight
	}

	scaledWeight, overflowed := basics.Muldiv(totalOnline.ToUint64()-provenWeight, halfPeriodForInterval-uint64(offset), halfPeriodForInterval)
	if overflowed {
		// Shouldn't happen, but a safe fallback is to accept a larger state proof.
		logger.Warnf("calculateAcceptableStateProofWeight(%d, %d, %d, %d) overflow scaledWeight",
			totalOnline, stateProofInterval, lastAttestedRound, firstValid)
		return 0
	}

	w, overflowed := basics.OAdd(provenWeight, scaledWeight)
	if overflowed {
		// Shouldn't happen, but a safe fallback is to accept a larger state proof.
		logger.Warnf("calculateAcceptableStateProofWeight(%d, %d, %d, %d) overflow provenWeight (%d) + scaledWeight (%d)",
			totalOnline, stateProofInterval, lastAttestedRound, firstValid, provenWeight, scaledWeight)
		return 0
	}

	return w
}

// GetProvenWeight computes the parameters for building or verifying
// a state proof for the interval (votersHdr, latestRoundInProofHdr], using voters from block votersHdr.
func GetProvenWeight(votersHdr *bookkeeping.BlockHeader, latestRoundInProofHdr *bookkeeping.BlockHeader) (uint64, error) {
	proto := config.Consensus[votersHdr.CurrentProtocol]

	if proto.StateProofInterval == 0 {
		return 0, errStateProofNotEnabled
	}

	if votersHdr.Round%basics.Round(proto.StateProofInterval) != 0 {
		err := fmt.Errorf("votersHdr %d not a multiple of %d",
			votersHdr.Round, proto.StateProofInterval)
		return 0, err
	}

	if latestRoundInProofHdr.Round != votersHdr.Round+basics.Round(proto.StateProofInterval) {
		err := fmt.Errorf("certifying block %d not %d ahead of voters %d",
			latestRoundInProofHdr.Round, proto.StateProofInterval, votersHdr.Round)
		return 0, err
	}

	totalWeight := votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight.ToUint64()
	provenWeight, overflowed := basics.Muldiv(totalWeight, uint64(proto.StateProofWeightThreshold), 1<<32)
	if overflowed {
		err := fmt.Errorf("overflow computing provenWeight[%d]: %d * %d / (1<<32)",
			latestRoundInProofHdr.Round, totalWeight, proto.StateProofWeightThreshold)
		return 0, err
	}

	return provenWeight, nil
}

// ValidateStateProof checks that a state proof is valid.
func ValidateStateProof(verificationData *ledgercore.StateProofVerificationData, stateProof *stateproof.StateProof, atRound basics.Round, msg *stateproofmsg.Message) error {
	proto := config.Consensus[verificationData.Version]

	if proto.StateProofInterval == 0 {
		return fmt.Errorf("rounds = %d: %w", proto.StateProofInterval, errStateProofNotEnabled)
	}

	if verificationData.TargetStateProofRound%basics.Round(proto.StateProofInterval) != 0 {
		return fmt.Errorf("state proof at %d for non-multiple of %d: %w", verificationData.TargetStateProofRound, proto.StateProofInterval, errNotAtRightMultiple)
	}

	acceptableWeight := calculateAcceptableStateProofWeight(verificationData.OnlineTotalWeight, proto.StateProofInterval, proto.StateProofWeightThreshold, verificationData.TargetStateProofRound, atRound, logging.Base())
	if stateProof.SignedWeight < acceptableWeight {
		return fmt.Errorf("insufficient weight at round %d: %d < %d: %w",
			atRound, stateProof.SignedWeight, acceptableWeight, errInsufficientWeight)
	}

	provenWeight, overflowed := basics.Muldiv(verificationData.OnlineTotalWeight.ToUint64(), uint64(proto.StateProofWeightThreshold), 1<<32)
	if overflowed {
		return fmt.Errorf("overflow computing provenWeight[%d]: %d * %d / (1<<32)",
			verificationData.TargetStateProofRound, verificationData.OnlineTotalWeight.ToUint64(), proto.StateProofWeightThreshold)

	}

	verifier, err := stateproof.MkVerifier(verificationData.VotersCommitment,
		provenWeight,
		config.Consensus[verificationData.Version].StateProofStrengthTarget)
	if err != nil {
		return err
	}

	err = verifier.Verify(uint64(verificationData.TargetStateProofRound), msg.Hash(), stateProof)
	if err != nil {
		return fmt.Errorf("%v: %w", err, errStateProofCrypto)
	}
	return nil
}
