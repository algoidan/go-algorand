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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestCertToJSON(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	p := generateCertForTesting(a, 4)
	cert := p.cc
	verif, err := MkVerifier(p.partCommitment, p.provenWeight, 4)
	a.NoError(err)

	err = verif.Verify(compactCertRoundsForTests, p.data, &cert)
	a.NoError(err, "failed to verify the compact cert")

	certenc, err := cert.createSnarkFriendlyCert(p.data[:])
	a.NoError(err)
	//fmt.Printf(string(protocol.EncodeJSON(certenc)))

	fmt.Printf(certenc.toZokCode())

}
