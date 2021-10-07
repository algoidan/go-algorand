// Copyright (C) 2019-2021 Algorand, Inc.
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

package account

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklekeystore"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type RoundSecrets struct {
	VRF    *crypto.VRFSecrets
	Voting *crypto.OneTimeSignatureSecrets
	// BlockProof is used to sign compact certificates. might be nil
	BlockProof *merklekeystore.Signer
}

type ParticipationSecrets struct {
	VRF    *crypto.VRFSecrets
	Voting *crypto.OneTimeSignatureSecrets
	// BlockProof is used to sign compact certificates. might be nil
	BlockProof *merklekeystore.Signer
}

type ParticipationDetails struct {
	Parent basics.Address

	// The first and last rounds for which this account is valid, respectively.
	//
	// When lastValid has concluded, this set of secrets is destroyed.
	FirstValid basics.Round
	LastValid  basics.Round

	KeyDilution uint64
}

// A Participation encapsulates a set of secrets which allows a root to
// participate in consensus. All such accounts are associated with a parent root
// account via the Address (although this parent account may not be
// resident on this machine).
//
// Participations are allowed to vote on a user's behalf for some range of
// rounds. After this range, all remaining secrets are destroyed.
//
// For correctness, all Roots should have no more than one Participation
// globally active at any time. If this condition is violated, the Root may
// equivocate. (Algorand tolerates a limited fraction of misbehaving accounts.)
type ParticipationWithSecrets struct {
	ParticipationDetails
	ParticipationSecrets
}

type ParticipationInRound struct {
	ParticipationDetails
	RoundSecrets
}

type SecretsId struct {
	VoteID       crypto.OneTimeSignatureVerifier
	SelectionID  crypto.VRFVerifier
	BlockProofID merklekeystore.Verifier
}

type Participation struct {
	ParticipationDetails
	SecretsId
}


// ValidInterval returns the first and last rounds for which this participation account is valid.
func (part  ParticipationDetails) ValidInterval() (first, last basics.Round) {
	return part.FirstValid, part.LastValid
}

// Address returns the root account under which this participation account is registered.
func (part ParticipationDetails) Address() basics.Address {
	return part.Parent
}

// OverlapsInterval returns true if the partkey is valid at all within the range of rounds (inclusive)
func (part ParticipationDetails) OverlapsInterval(first, last basics.Round) bool {
	if last < first {
		logging.Base().Panicf("Round interval should be ordered (first = %v, last = %v)", first, last)
	}
	if last < part.FirstValid || first > part.LastValid {
		return false
	}
	return true
}

// VRFSecrets returns the VRF secrets associated with this Participation account.
func (part ParticipationInRound) VRFSecrets() *crypto.VRFSecrets {
	return part.VRF
}

// VotingSecrets returns the voting secrets associated with this Participation account.
func (part ParticipationWithSecrets) VotingSecrets() *crypto.OneTimeSignatureSecrets {
	return part.Voting
}

// VotingSigner returns the voting secrets associated with this Participation account,
// together with the KeyDilution value.
func (part ParticipationInRound) VotingSigner() crypto.OneTimeSigner {
	return crypto.OneTimeSigner{
		OneTimeSignatureSecrets: part.Voting,
		OptionalKeyDilution:     part.KeyDilution,
	}
}

// BlockProofSigner returns the key used to sign on Compact Certificates.
// might return nil!
func (part ParticipationWithSecrets) BlockProofSigner() *merklekeystore.Signer {
	return part.BlockProof
}

// GenerateRegistrationTransaction returns a transaction object for registering a Participation with its parent.
func (part Participation) GenerateRegistrationTransaction(fee basics.MicroAlgos, txnFirstValid, txnLastValid basics.Round, leaseBytes [32]byte, cparams config.ConsensusParams) transactions.Transaction {
	t := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:     part.Parent,
			Fee:        fee,
			FirstValid: txnFirstValid,
			LastValid:  txnLastValid,
			Lease:      leaseBytes,
		},
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK:      part.VoteID,
			SelectionPK: part.SelectionID,
		},
	}
	//if cert := part.BlockProofID; cert != nil {
	//	if cparams.EnableBlockProofKeyregCheck {
	//		t.KeyregTxnFields.BlockProofPK = *(cert.GetVerifier())
	//	}
	//}
	t.KeyregTxnFields.VoteFirst = part.FirstValid
	t.KeyregTxnFields.VoteLast = part.LastValid
	t.KeyregTxnFields.VoteKeyDilution = part.KeyDilution
	return t
}
