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
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"strconv"
	"testing"

	cfalcon "github.com/algoidan/falcon"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklekeystore"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/stretchr/testify/require"
)

type testMessage string

const compactCertRoundsForTests = 128

func (m testMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, []byte(m)
}

func createParticipantSliceWithWeight(totalWeight, numberOfParticipant int, key *merklekeystore.Signer) []basics.Participant {
	parts := make([]basics.Participant, 0, numberOfParticipant)

	for i := 0; i < numberOfParticipant; i++ {
		part := basics.Participant{
			PK:     *key.GetVerifier(),
			Weight: uint64(totalWeight / 2 / numberOfParticipant),
		}

		parts = append(parts, part)
	}
	return parts
}

func generateTestSigner(name string, firstValid uint64, lastValid uint64, interval uint64, a *require.Assertions) (*merklekeystore.Signer, db.Accessor) {
	store, err := db.MakeAccessor(name, false, true)
	a.NoError(err)
	a.NotNil(store)

	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err = tx.Exec(`CREATE TABLE schema (
         tablename TEXT PRIMARY KEY,
         version INTEGER
      );`)
		return err
	})
	a.NoError(err)

	signer, err := merklekeystore.New(firstValid, lastValid, interval, SignatureScheme, store)
	a.NoError(err)

	err = signer.Persist()
	a.NoError(err)

	return signer, store
}

func TestBuildVerify(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	currentRound := basics.Round(128)
	// Doing a full test of 1M accounts takes too much CPU time in CI.
	doLargeTest := false

	totalWeight := 10000000
	npartHi := 10
	npartLo := 9990

	if doLargeTest {
		npartHi *= 100
		npartLo *= 100
	}

	npart := npartHi + npartLo

	param := Params{
		Msg:          testMessage("hello world"),
		ProvenWeight: uint64(totalWeight / 2),
		SigRound:     currentRound,
		SecKQ:        128,
	}

	// Share the key; we allow the same vote key to appear in multiple accounts..
	key, dbAccessor := generateTestSigner(t.Name()+".db", 0, uint64(compactCertRoundsForTests)+1, compactCertRoundsForTests, a)
	defer dbAccessor.Close()
	require.NotNil(t, dbAccessor, "failed to create signer")
	var parts []basics.Participant
	var sigs []merklekeystore.Signature
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartHi, key)...)
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartLo, key)...)

	sig, err := key.Sign(param.Msg, uint64(currentRound))
	require.NoError(t, err, "failed to create keys")

	for i := 0; i < npart; i++ {
		sigs = append(sigs, sig)
	}

	partcom, err := merklearray.Build(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	if err != nil {
		t.Error(err)
	}

	b, err := MkBuilder(param, parts, partcom)
	if err != nil {
		t.Error(err)
	}

	for i := 0; i < npart; i++ {
		err = b.Add(uint64(i), sigs[i], !doLargeTest)
		if err != nil {
			t.Error(err)
		}
	}

	cert, err := b.Build()
	if err != nil {
		t.Error(err)
	}

	var someReveal Reveal
	for _, rev := range cert.Reveals {
		someReveal = rev
		break
	}

	certenc := protocol.Encode(cert)
	fmt.Printf("Cert size:\n")
	fmt.Printf("  %6d elems sigproofs\n", len(cert.SigProofs.Path))
	fmt.Printf("  %6d bytes sigproofs\n", len(protocol.EncodeReflect(cert.SigProofs)))
	fmt.Printf("  %6d bytes partproofs\n", len(protocol.EncodeReflect(cert.PartProofs)))
	fmt.Printf("  %6d bytes sigproof per reveal\n", len(protocol.EncodeReflect(cert.SigProofs))/len(cert.Reveals))
	fmt.Printf("  %6d reveals:\n", len(cert.Reveals))
	fmt.Printf("    %6d bytes reveals[*] participant\n", len(protocol.Encode(&someReveal.Part)))
	fmt.Printf("    %6d bytes reveals[*] sigslot\n", len(protocol.Encode(&someReveal.SigSlot)))
	fmt.Printf("    %6d bytes reveals[*] total\n", len(protocol.Encode(&someReveal)))
	fmt.Printf("  %6d bytes total\n", len(certenc))

	verif := MkVerifier(param, partcom.Root())
	err = verif.Verify(cert)
	require.NoError(t, err, "failed to verify the compact cert")
}

func generateRandomParticipant(a *require.Assertions, testname string) basics.Participant {
	key, dbAccessor := generateTestSigner(testname+".db", 0, 8, 1, a)
	a.NotNil(dbAccessor, "failed to create signer")
	defer dbAccessor.Close()

	p := basics.Participant{
		PK:     *key.GetVerifier(),
		Weight: crypto.RandUint64(),
	}
	return p
}

func calculateHashOnPartLeaf(part basics.Participant) []byte {
	binaryWeight := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryWeight, part.Weight)

	publicKeyBytes := part.PK
	partCommitment := make([]byte, 0, len(protocol.CompactCertPart)+len(binaryWeight)+len(publicKeyBytes))
	partCommitment = append(partCommitment, protocol.CompactCertPart...)
	partCommitment = append(partCommitment, binaryWeight...)
	partCommitment = append(partCommitment, publicKeyBytes[:]...)

	factory := crypto.HashFactory{HashType: HashType}
	hashValue := crypto.HashBytes(factory.NewHash(), partCommitment)
	return hashValue
}

func calculateHashOnSigLeaf(t *testing.T, sig merklekeystore.Signature, lValue uint64) []byte {

	var sigCommitment []byte
	sigCommitment = append(sigCommitment, protocol.CompactCertSig...)

	binaryL := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryL, lValue)

	sigCommitment = append(sigCommitment, binaryL...)

	// verify the falcon usage
	require.Equal(t, sig.VerifyingKey.Type, crypto.FalconType)
	compressedFalconsSig := cfalcon.CompressedSignature(sig.ByteSignature)
	ctFalconSig, err := compressedFalconsSig.ConvertToCT()
	ctFalconSigBytes := ctFalconSig[:]
	falconPK := sig.VerifyingKey.FalconPublicKey.PublicKey[:]

	require.NoError(t, err)
	//build the expected binary representation of the merkle signature
	sigCommitment = append(sigCommitment, ctFalconSigBytes...)
	sigCommitment = append(sigCommitment, falconPK...)

	treeIdxBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(treeIdxBytes, sig.MerkleArrayIndex)
	sigCommitment = append(sigCommitment, treeIdxBytes...)

	//build the expected binary representation of the merkle signature proof

	proofLen := len(sig.Proof.Path)
	proofLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(proofLenBytes, uint32(proofLen))

	sigCommitment = append(sigCommitment, proofLenBytes...)

	for i := 0; i < proofLen; i++ {
		sigCommitment = append(sigCommitment, sig.Proof.Path[i]...)
	}

	factory := crypto.HashFactory{HashType: HashType}
	hashValue := crypto.HashBytes(factory.NewHash(), sigCommitment)
	return hashValue
}

func calculateHashOnInternalNode(leftNode, rightNode []byte) []byte {
	buf := make([]byte, len(leftNode)+len(rightNode)+len(protocol.MerkleArrayNode))
	copy(buf[:], protocol.MerkleArrayNode)
	copy(buf[len(protocol.MerkleArrayNode):], leftNode[:])
	copy(buf[len(protocol.MerkleArrayNode)+len(leftNode):], rightNode[:])

	factory := crypto.HashFactory{HashType: HashType}
	hashValue := crypto.HashBytes(factory.NewHash(), buf)
	return hashValue
}

// This test makes sure that cert's signature commitment is according to spec and stays sync with the
// SNARK verifier. This test enforces a specific binary representation of the merkle's tree leaves.
// in case this test breaks, the SNARK verifier should be updated accordingly
func TestParticipationCommitment(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var parts []basics.Participant
	parts = append(parts, generateRandomParticipant(a, t.Name()))
	parts = append(parts, generateRandomParticipant(a, t.Name()))
	parts = append(parts, generateRandomParticipant(a, t.Name()))
	parts = append(parts, generateRandomParticipant(a, t.Name()))

	partcom, err := merklearray.Build(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	partCommitmentRoot := partcom.Root()

	leaf0 := calculateHashOnPartLeaf(parts[0])
	leaf1 := calculateHashOnPartLeaf(parts[1])
	leaf2 := calculateHashOnPartLeaf(parts[2])
	leaf3 := calculateHashOnPartLeaf(parts[3])

	inner1 := calculateHashOnInternalNode(leaf0, leaf1)
	inner2 := calculateHashOnInternalNode(leaf2, leaf3)

	calcRoot := calculateHashOnInternalNode(inner1, inner2)

	a.Equal(partCommitmentRoot, crypto.GenericDigest(calcRoot))

}

// This test makes sure that cert's signature commitment is according to spec and stays sync with the
// SNARK verifier. This test enforces the usage of falcon signature and a specific binary representation
// of the merkle's tree leaves.
// in case this test breaks, the SNARK verifier should be updated accordingly
func TestSignatureCommitment(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	currentRound := basics.Round(128)
	totalWeight := 10000000
	numPart := 4

	param := Params{
		Msg:          testMessage("test!"),
		ProvenWeight: uint64(totalWeight / (2 * numPart)),
		SigRound:     currentRound,
		SecKQ:        128,
	}

	var parts []basics.Participant
	var sigs []merklekeystore.Signature

	for i := 0; i < numPart; i++ {
		key, dbAccessor := generateTestSigner(t.Name()+".db", 0, uint64(compactCertRoundsForTests)*8, compactCertRoundsForTests, a)
		require.NotNil(t, dbAccessor, "failed to create signer")

		part := basics.Participant{
			PK:     *key.GetVerifier(),
			Weight: uint64(totalWeight / 2 / numPart),
		}
		parts = append(parts, part)

		sig, err := key.Sign(param.Msg, uint64(currentRound))
		require.NoError(t, err, "failed to create keys")
		sigs = append(sigs, sig)

		dbAccessor.Close()
	}

	partcom, err := merklearray.Build(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	b, err := MkBuilder(param, parts, partcom)
	a.NoError(err)

	for i := 0; i < numPart; i++ {
		err = b.Add(uint64(i), sigs[i], false)
		a.NoError(err)
	}

	cert, err := b.Build()
	a.NoError(err)

	leaf0 := calculateHashOnSigLeaf(t, sigs[0], findLInCert(a, sigs[0], cert))
	leaf1 := calculateHashOnSigLeaf(t, sigs[1], findLInCert(a, sigs[1], cert))
	leaf2 := calculateHashOnSigLeaf(t, sigs[2], findLInCert(a, sigs[2], cert))
	leaf3 := calculateHashOnSigLeaf(t, sigs[3], findLInCert(a, sigs[3], cert))

	inner1 := calculateHashOnInternalNode(leaf0, leaf1)
	inner2 := calculateHashOnInternalNode(leaf2, leaf3)

	calcRoot := calculateHashOnInternalNode(inner1, inner2)

	a.Equal(cert.SigCommit, crypto.GenericDigest(calcRoot))

}

func findLInCert(a *require.Assertions, signature merklekeystore.Signature, cert *Cert) uint64 {
	for _, t := range cert.Reveals {
		if bytes.Compare(t.SigSlot.Sig.Signature.ByteSignature, signature.ByteSignature) == 0 {
			return t.SigSlot.L
		}
	}
	a.Fail("could not find matching reveal")
	return 0
}

func BenchmarkBuildVerify(b *testing.B) {
	totalWeight := 1000000
	npart := 10000

	currentRound := basics.Round(128)
	a := require.New(b)

	param := Params{
		Msg:          testMessage("hello world"),
		ProvenWeight: uint64(totalWeight / 2),
		SigRound:     128,
		SecKQ:        128,
	}

	var parts []basics.Participant
	var partkeys []*merklekeystore.Signer
	var sigs []merklekeystore.Signature
	for i := 0; i < npart; i++ {
		key, dbAccessor := generateTestSigner(b.Name()+"_"+strconv.Itoa(i)+"_crash.db", 0, uint64(compactCertRoundsForTests)+1, compactCertRoundsForTests, a)
		defer dbAccessor.Close()
		require.NotNil(b, dbAccessor, "failed to create signer")
		part := basics.Participant{
			PK:     *key.GetVerifier(),
			Weight: uint64(totalWeight / npart),
		}

		sig, err := key.Sign(param.Msg, uint64(currentRound))
		require.NoError(b, err, "failed to create keys")

		partkeys = append(partkeys, key)
		sigs = append(sigs, sig)
		parts = append(parts, part)
	}

	var cert *Cert
	partcom, err := merklearray.Build(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	if err != nil {
		b.Error(err)
	}

	b.Run("AddBuild", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			builder, err := MkBuilder(param, parts, partcom)
			if err != nil {
				b.Error(err)
			}

			for i := 0; i < npart; i++ {
				err = builder.Add(uint64(i), sigs[i], true)
				if err != nil {
					b.Error(err)
				}
			}

			cert, err = builder.Build()
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			verif := MkVerifier(param, partcom.Root())
			if err = verif.Verify(cert); err != nil {
				b.Error(err)
			}
		}
	})
}

func TestCoinIndex(t *testing.T) {
	partitiontest.PartitionTest(t)

	n := 1000
	b := &Builder{
		sigs:          make([]sigslot, n),
		sigsHasValidL: true,
	}

	for i := 0; i < n; i++ {
		b.sigs[i].L = uint64(i)
		b.sigs[i].Weight = 1
	}

	for i := 0; i < n; i++ {
		pos, err := b.coinIndex(uint64(i))
		require.NoError(t, err)
		require.Equal(t, pos, uint64(i))
	}
}
