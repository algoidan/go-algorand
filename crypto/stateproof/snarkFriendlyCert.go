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
	"os"

	"text/template"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
)

type snarkFriendlySigslotCommit struct {
	_struct struct{} `codec:""`

	Sig merklesignature.SnarkFriendlySignature `codec:"s"`
	L   uint64                                 `codec:"l"`
}

type snarkFriendlyReveal struct {
	_struct struct{} `codec:""`

	Position  uint64                      `codec:"pos"`
	SigSlot   snarkFriendlySigslotCommit  `codec:"s"`
	SigProof  merklearray.SingleLeafProof `codec:"sp"`
	Part      basics.Participant          `codec:"p"`
	PartProof merklearray.SingleLeafProof `codec:"pp"`
}

type snarkFriendlyCert struct {
	_struct struct{} `codec:""`

	SigCommit                  crypto.GenericDigest  `codec:"c"`
	SignedWeight               uint64                `codec:"w"`
	MerkleSignatureSaltVersion byte                  `codec:"v"`
	Reveals                    []snarkFriendlyReveal `codec:"r,allocbound=MaxReveals"`
}

func (c *Cert) createSnarkFriendlyCert(data []byte) (*snarkFriendlyCert, error) {
	newData := make([]byte, len(data))
	copy(newData, data)

	sigs := make(map[uint64]crypto.Hashable)
	parts := make(map[uint64]crypto.Hashable)

	for pos, r := range c.Reveals {
		sig, err := buildCommittableSignature(r.SigSlot)
		if err != nil {
			return nil, err
		}

		sigs[pos] = sig
		parts[pos] = r.Part
	}

	reveals := make([]snarkFriendlyReveal, 0, len(c.PositionsToReveal))
	for i := 0; i < len(c.PositionsToReveal); i++ {
		position := c.PositionsToReveal[i]
		reveal, ok := c.Reveals[position]
		if !ok {
			return nil, fmt.Errorf("could not find position on reveals map")
		}
		sigWithHints, err := reveal.SigSlot.Sig.CreateSNARKFriendlySignature(newData)
		if err != nil {
			return nil, err
		}
		paddedMssProof := merklearray.PadProofToMaxDepth(&reveal.SigSlot.Sig.Proof)
		sigWithHints.Proof.Path = paddedMssProof

		singleSigProof, err := merklearray.DecompressProofVC(sigs, &c.SigProofs, position)
		if err != nil {
			return nil, err
		}
		paddedSigProof := merklearray.PadProofToMaxDepth(singleSigProof)
		singleSigProof.Path = paddedSigProof

		singlePartProof, err := merklearray.DecompressProofVC(parts, &c.PartProofs, position)
		if err != nil {
			return nil, err
		}
		paddedPartProof := merklearray.PadProofToMaxDepth(singlePartProof)
		singlePartProof.Path = paddedPartProof

		sigSlot := snarkFriendlySigslotCommit{L: reveal.SigSlot.L, Sig: sigWithHints}
		reveals = append(reveals, snarkFriendlyReveal{
			Position:  position,
			SigSlot:   sigSlot,
			SigProof:  *singleSigProof,
			Part:      reveal.Part,
			PartProof: *singlePartProof})
	}

	return &snarkFriendlyCert{
		SigCommit:                  c.SigCommit,
		SignedWeight:               c.SignedWeight,
		MerkleSignatureSaltVersion: c.MerkleSignatureSaltVersion,
		Reveals:                    reveals,
	}, nil
}

func (c *snarkFriendlyCert) toZokCode() string {
	// todo use the consts
	var sigTemplate = `StateProof<16,16,1024> s =  StateProof {
		salt_version: {{.MerkleSignatureSaltVersion}},
		signed_weight: {{.SignedWeight}},
		vc_signatures: {{.SigCommit}},
		num_reveals: {{len .Reveals}},
		reveals: [{{ range $index, $element := .Reveals}}{{if $index}},{{end}}
		Reveal {
			index: {{.Position}},
			participant: Participant {
					weight: {{.Part.Weight}},
					pk_mss: {{.Part.PK}},
				},
			sigslot: SignatureSlot {
					L: {{.SigSlot.L}},
					mss_signature: Sig {
						index: {{.SigSlot.Sig.Signature.VectorCommitmentIndex}},
						ephemeral_falcon_pk: {{.SigSlot.Sig.Signature.VerifyingKey.PublicKey}},
						proof: Proof {
							digests: {{.SigSlot.Sig.Signature.Proof.Proof.Path}},
							depth: {{.SigSlot.Sig.Signature.Proof.Proof.TreeDepth}},
						},
						falcon_ct_sig: {{.SigSlot.Sig.CTSignature}},
						s1_hint: {{.SigSlot.Sig.S1Values}},
					}
				},
			proof_participant: Proof {
					digests: {{.PartProof.Path}},
					depth: {{.PartProof.TreeDepth}},
				},
			proof_sigslot: Proof {
					digests: {{.SigProof.Path}},
					depth: {{.SigProof.TreeDepth}},
				},
		}{{ end }}],
	}`

	t, err := template.New("zok").Parse(sigTemplate)
	if err != nil {
		panic(err)
	}
	err = t.Execute(os.Stdout, c)
	if err != nil {
		panic(err)
	}
	return ""
}
