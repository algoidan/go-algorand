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

package merklekeystore

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func calculateHashOnKeyLeaf(key *crypto.GenericSigningKey, round uint64) []byte {
	binaryRound := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryRound, round)

	schemeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(schemeBytes, uint16(key.Type))

	verifyingRawKey := key.GetSigner().GetVerifyingKey().GetVerifier().GetVerificationBytes()
	keyCommitment := make([]byte, 0, len(protocol.KeystorePK)+len(verifyingRawKey)+len(binaryRound))

	keyCommitment = append(keyCommitment, protocol.KeystorePK...)
	keyCommitment = append(keyCommitment, schemeBytes...)
	keyCommitment = append(keyCommitment, binaryRound...)
	keyCommitment = append(keyCommitment, verifyingRawKey...)

	factory := crypto.HashFactory{HashType: KeyStoreHashFunction}
	hashValue := crypto.HashBytes(factory.NewHash(), keyCommitment)
	return hashValue
}

func calculateHashOnInternalNode(leftNode, rightNode []byte) []byte {
	buf := make([]byte, len(leftNode)+len(rightNode)+len(protocol.MerkleArrayNode))
	copy(buf[:], protocol.MerkleArrayNode)
	copy(buf[len(protocol.MerkleArrayNode):], leftNode[:])
	copy(buf[len(protocol.MerkleArrayNode)+len(leftNode):], rightNode[:])

	factory := crypto.HashFactory{HashType: KeyStoreHashFunction}
	hashValue := crypto.HashBytes(factory.NewHash(), buf)
	return hashValue
}

func TestEphemeralPublicKeysCommitmentBinaryFormat(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(crypto.FalconType, 1, 9, 2, a)
	defer signer.keyStore.store.Close()
	a.Equal(4, length(signer, a))

	k0, err := signer.keyStore.GetKey(2)
	a.NoError(err)
	k0hash := calculateHashOnKeyLeaf(k0, 2)

	k1, err := signer.keyStore.GetKey(4)
	a.NoError(err)
	k1hash := calculateHashOnKeyLeaf(k1, 4)

	k2, err := signer.keyStore.GetKey(6)
	a.NoError(err)
	k2hash := calculateHashOnKeyLeaf(k2, 6)

	k3, err := signer.keyStore.GetKey(8)
	a.NoError(err)
	k3hash := calculateHashOnKeyLeaf(k3, 8)

	internal1 := calculateHashOnInternalNode(k0hash, k1hash)
	internal2 := calculateHashOnInternalNode(k2hash, k3hash)

	root := calculateHashOnInternalNode(internal1, internal2)
	a.Equal(root, signer.GetVerifier()[:])
}
