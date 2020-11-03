// SPDX-FileCopyrightText: 2020 Matthias Axel Kröll
// SPDX-FileCopyrightText: 2020 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package bpv7

import "io"

// BlockConfidentialityBlock implements the BPSEC Block Confidentiality Block (BCB)
type BlockConfidentialityBlock struct {
	abstractSecurityBlock AbstractSecurityBlock
}

// BlockTypeCode must return a constant integer, indicating the block type code.
func (bib *BlockConfidentialityBlock) BlockCodeType() uint64 {
	return ExtBlockTypeBlockConfidentialityBlock
}

// MarshalCbor writes a CBOR representation for a Bundle Confidentiality Block.
func (bib *BlockConfidentialityBlock) MarshalCbor(w io.Writer) error {
	return nil
}

// UnmarshalCbor writes a CBOR representation for a Bundle Confidentiality Block
func (bib *BlockConfidentialityBlock) UnmarshalCbor(w io.Writer) error {
	return nil
}

// CheckValid returns an array of errors for incorrect data.
func (bib *BlockConfidentialityBlock) CheckValid() error {
	return nil
}
