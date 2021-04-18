// SPDX-FileCopyrightText: 2020 Matthias Axel Kröll
// SPDX-FileCopyrightText: 2020 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package bpv7

import (
	"io"

	"github.com/dtn7/cboring"
)

// BIBIOPHMACSHA2 implements the BPSEC Block Integrity Block (BIB)
type BIBIOPHMACSHA2 struct {
	asb AbstractSecurityBlock
}

// BlockTypeCode must return a constant integer, indicating the block type code.
func (bib *BIBIOPHMACSHA2) BlockCodeType() uint64 {
	return ExtBlockTypeBlockIntegrityBlock
}

// BlockTypeName must return a constant string, this block's name.
func (bib *BIBIOPHMACSHA2) BlockTypeName() string {
	return SecConNameBIBIOPHMACSHA
}

// MarshalCbor writes a CBOR representation for a Bundle Integrity Block.
func (bib *BIBIOPHMACSHA2) MarshalCbor(w io.Writer) error {
	return bib.asb.MarshalCbor(w)
}

// UnmarshalCbor writes a CBOR representation for a Bundle Integrity Block
func (bib *BIBIOPHMACSHA2) UnmarshalCbor(r io.Reader) error {
	return bib.asb.UnmarshalCbor(r)
}

// CheckValid returns an array of errors for incorrect data.
func (bib *BIBIOPHMACSHA2) CheckValid() error {
	if err := bib.asb.CheckValid(); err != nil {
		return err
	}

	return nil
}

func (bib *BIBIOPHMACSHA2) PrepareIPPT(b Bundle, securityTargetBlockNumber uint64) (ippt io.Writer, err error) {
	if bib.asb.HasSecurityContextParametersPresentContextFlag() {
		for _, scp := range bib.asb.SecurityContextParameters {
			if scp.ID() == SecParIdentBIBIOPHMACSHA2IntegrityScopeFlags {
				integrityScopeFlag := uint16(scp.Value().(uint64))

				if integrityScopeFlag&PrimaryBlockFlag == PrimaryBlockFlag {
					if err = b.PrimaryBlock.MarshalCbor(ippt); err != nil {
						return nil, err
					}
				}

				if integrityScopeFlag&SecurityHeaderFlag == SecurityHeaderFlag {
					if err = cboring.WriteUInt(bib.BlockCodeType(), ippt); err != nil {
						return nil, err
					}

					var bibCanonicalBlock *CanonicalBlock
					bibCanonicalBlock, err = b.ExtensionBlock(bib.BlockCodeType())
					if err != nil {
						return nil, err
					}

					if err = cboring.WriteUInt(bibCanonicalBlock.BlockNumber, ippt); err != nil {
						return nil, err
					}

					if err = cboring.WriteUInt(uint64(bibCanonicalBlock.BlockControlFlags), ippt); err != nil {
						return nil, err
					}

				}

				if integrityScopeFlag&TargetHeaderFlag == TargetHeaderFlag {
					for _, block := range b.CanonicalBlocks {
						if block.BlockNumber == securityTargetBlockNumber {

							return nil, nil
						}
					}
				}

			}
		}
	}

	return ippt, nil
}

// Creates a new
