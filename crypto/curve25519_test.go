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

package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func GetPreGeneratedKey() *SignatureSecrets {
	secKey := [64]byte{0x49, 0xd4, 0xcd, 0x9c, 0x99, 0x43, 0xce, 0xaf, 0xc, 0x5b, 0x3f, 0x9a, 0xfa, 0xbc, 0x9c, 0xd9, 0x19, 0x71, 0x69, 0x50, 0x90, 0xb6, 0x30, 0x3b, 0xf5, 0x1d, 0x3f, 0x73, 0x43, 0xe8, 0xb4, 0x22, 0x2e, 0x74, 0x5, 0xfe, 0xc6, 0x99, 0xa2, 0xa5, 0xd4, 0xf8, 0x9e, 0xcf, 0x38, 0xd6, 0x28, 0x28, 0xe6, 0xd0, 0x72, 0x9b, 0x9c, 0x4c, 0xea, 0x27, 0xd5, 0xe5, 0x99, 0xa3, 0xc4, 0x43, 0x2a, 0x39}
	var pub [32]byte
	copy(pub[:], secKey[32:])
	secrets := SignatureSecrets{}
	secrets.SK = secKey
	secrets.SignatureVerifier = pub
	return &secrets
}

func makeCurve25519Secret() *SignatureSecrets {
	var s Seed
	RandBytes(s[:])
	return GenerateSignatureSecrets(s)
}

func TestSignVerifyEmptyMessage(t *testing.T) {
	partitiontest.PartitionTest(t)
	pk, sk := ed25519GenerateKey()
	sig := ed25519Sign(sk, []byte{})
	if !ed25519Verify(pk, []byte{}, sig, true) {
		t.Errorf("sig of an empty message failed to verify")
	}
}

func TestVerifyZeros(t *testing.T) {
	partitiontest.PartitionTest(t)
	var pk SignatureVerifier
	var sig Signature
	for x := byte(0); x < 255; x++ {
		if pk.VerifyBytes([]byte{x}, sig, true) {
			t.Errorf("Zero sig with zero pk successfully verified message %x", x)
		}
	}
}

func TestGenerateSignatureSecrets(t *testing.T) {
	partitiontest.PartitionTest(t)
	var s Seed
	RandBytes(s[:])
	ref := GenerateSignatureSecrets(s)
	for i := 0; i < 10; i++ {
		secrets := GenerateSignatureSecrets(s)
		if bytes.Compare(ref.SignatureVerifier[:], secrets.SignatureVerifier[:]) != 0 {
			t.Errorf("SignatureSecrets.SignatureVerifier is inconsistent; different results generated for the same seed")
			return
		}
		if bytes.Compare(ref.SK[:], secrets.SK[:]) != 0 {
			t.Errorf("SignatureSecrets.SK is inconsistent; different results generated for the same seed")
			return
		}
	}
}

func TestCurve25519SignVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	signVerify(t, makeCurve25519Secret(), makeCurve25519Secret())
}

func TestVRFProveVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	proveVerifyVrf(t, GenerateVRFSecrets(), GenerateVRFSecrets())
}

func BenchmarkSignVerify(b *testing.B) {
	c := makeCurve25519Secret()
	s := randString()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sig := c.Sign(s)
		_ = c.Verify(s, sig, true)
	}
}

func BenchmarkSign(b *testing.B) {
	c := makeCurve25519Secret()
	s := randString()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = c.Sign(s)
	}
}
func BenchmarkVerify(b *testing.B) {
	c := makeCurve25519Secret()
	strs := make([]TestingHashable, b.N)
	sigs := make([]Signature, b.N)
	for i := 0; i < b.N; i++ {
		strs[i] = randString()
		sigs[i] = c.Sign(strs[i])
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = c.Verify(strs[i], sigs[i], true)
	}
}

func TestVerificationPreGeneratedKey(t *testing.T) {
	partitiontest.PartitionTest(t)
	secrets := GetPreGeneratedKey()

	m := TestingHashable{[]byte{0x34, 0x32}}
	signature := secrets.Sign(m)
	assert.Equal(t, true, secrets.SignatureVerifier.Verify(m, signature, true))
	assert.Equal(t, false, secrets.SignatureVerifier.Verify(m, signature, false))
}
