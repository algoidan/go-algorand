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
	"context"
	"database/sql"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklekeystore"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)


// PersistedParticipation encapsulates the static state of the participation
// for a single address at any given moment, while providing the ability
// to handle persistence and deletion of secrets.
type PersistedParticipation struct {
	ParticipationDetails
	Store db.Accessor
}

// DeleteOldKeys securely deletes ephemeral keys for rounds strictly older than the given round.
func (part PersistedParticipation) DeleteOldKeys(current basics.Round, proto config.ConsensusParams) <-chan error {
	//keyDilution := part.Details.KeyDilution
	//if keyDilution == 0 {
	//	keyDilution = proto.DefaultKeyDilution
	//}
	//
	//part.Secrets.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(current, keyDilution), keyDilution)

	errorCh := make(chan error, 1)
	//deleteOldKeys := func(encodedVotingSecrets []byte) {
	//	errorCh <- part.Store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
	//		_, err := tx.Exec("UPDATE ParticipationAccount SET voting=?", encodedVotingSecrets)
	//		if err != nil {
	//			return fmt.Errorf("Participation.DeleteOldKeys: failed to update account: %v", err)
	//		}
	//		return nil
	//	})
	//	close(errorCh)
	//}
	//voting := part.Secrets.Voting.Snapshot()
	//encodedVotingSecrets := protocol.Encode(&voting)
	//go deleteOldKeys(encodedVotingSecrets)
	return errorCh
}

// PersistNewParent writes a new parent address to the partkey database.
func (part PersistedParticipation) PersistNewParent() error {
	//return part.Store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
	//	_, err := tx.Exec("UPDATE ParticipationAccount SET parent=?", part.Details.Parent[:])
	//	return err
	//})
	return nil
}

// FillDBWithParticipationKeys initializes the passed database with participation keys
func FillDBWithParticipationKeys(store db.Accessor, address basics.Address, firstValid, lastValid basics.Round, keyDilution uint64) (part PersistedParticipation, err error) {
	if lastValid < firstValid {
		err = fmt.Errorf("FillDBWithParticipationKeys: lastValid %d is after firstValid %d", lastValid, firstValid)
		return
	}

	// Compute how many distinct participation keys we should generate
	firstID := basics.OneTimeIDForRound(firstValid, keyDilution)
	lastID := basics.OneTimeIDForRound(lastValid, keyDilution)
	numBatches := lastID.Batch - firstID.Batch + 1

	// Generate them
	v := crypto.GenerateOneTimeSignatureSecrets(firstID.Batch, numBatches)

	// Generate a new VRF key, which lives in the participation keys db
	vrf := crypto.GenerateVRFSecrets()

	// TODO change this
	compactCertRound := config.Consensus[protocol.ConsensusFuture].CompactCertRounds

	// Generate a new key which signs the compact certificates
	blockProof, err := merklekeystore.New(uint64(firstValid), uint64(lastValid), compactCertRound, crypto.DilithiumType, store)
	if err != nil {
		return PersistedParticipation{}, err
	}

	partDetails := 	ParticipationDetails{
		Parent:      address,
		FirstValid:  firstValid,
		LastValid:   lastValid,
		KeyDilution: keyDilution,
	}
	participationWithSecrets := ParticipationWithSecrets{
		partDetails,
		ParticipationSecrets{
			VRF:         vrf,
			Voting:      v,
			BlockProof:  blockProof,
		},
	}

	// Construct the Participation containing these keys to be persisted
	part = PersistedParticipation{
		partDetails,
		store,
	}
	// Persist the Participation into the database
	err = part.Persist(participationWithSecrets)
	if err != nil {
		return PersistedParticipation{}, err
	}

	err = blockProof.Persist() // must be called after part.Persist() !

	return part, err
}

// Persist writes a Participation out to a database on the disk
func (part PersistedParticipation) Persist(partWithSecrets ParticipationWithSecrets) error {
	rawVRF := protocol.Encode(partWithSecrets.VRF)
	voting := partWithSecrets.Voting.Snapshot()
	rawVoting := protocol.Encode(&voting)
	rawbBlockProof := protocol.Encode(partWithSecrets.BlockProof)

	err := part.Store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err := partInstallDatabase(tx)
		if err != nil {
			return fmt.Errorf("failed to install database: %w", err)
		}

		_, err = tx.Exec("INSERT INTO ParticipationAccount (parent, vrf, voting, blockProof, firstValid, lastValid, keyDilution) VALUES (?, ?, ?, ?, ?, ?,?)",
			part.Parent[:], rawVRF, rawVoting, rawbBlockProof, part.FirstValid, part.LastValid, part.KeyDilution)
		if err != nil {
			return fmt.Errorf("failed to insert account: %w", err)
		}
		return nil
	})

	if err != nil {
		err = fmt.Errorf("PersistedParticipation.Persist: %w", err)
	}
	return err

}

// Migrate is called when loading participation keys.
// Calls through to the migration helper and returns the result.
func Migrate(partDB db.Accessor) error {
	return partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return partMigrate(tx)
	})
}

// Close closes the underlying database handle.
func (part PersistedParticipation) Close() {
	part.Store.Close()
}

func (part *PersistedParticipation) GetParticipationInRound() ParticipationInRound {
	return ParticipationInRound{}
}
func (part *PersistedParticipation) GetParticipationData() Participation {
	return Participation{}
}

func (part *PersistedParticipation) GetParticipationDetails() ParticipationDetails {
	return ParticipationDetails{}
}

func (part *PersistedParticipation) GetParticipationWithSecrets() ParticipationWithSecrets {
	return ParticipationWithSecrets{}
}

