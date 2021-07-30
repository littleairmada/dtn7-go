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

// BIB-HMAC-SHA2 Security Parameters
const (
	SecParIdentBIBIOPHMACSHA2ShaVariant uint64 = 1

	SecParIdentBIBIOPHMACSHA2WrappedKey uint64 = 2

	SecParIdentBIBIOPHMACSHA2IntegrityScopeFlags uint64 = 3
)

// SecConResultIDBIBIOPHMACSHA2ExpectedHMAC BIB-IOP-HMAC-SHA2 ResultID
const SecConResultIDBIBIOPHMACSHA2ExpectedHMAC uint64 = 1

// SHA Variant Parameter Values for BIB-IOP-HMAC-SHA2.
const (
	HMAC256SHA256 uint64 = 5 // Default
	HMAC384SHA384 uint64 = 6
	HMAC512SHA512 uint64 = 7
)

// IntegrityScopeFlags are used to show how broadly how broadly the concept of integrity is being applied, e.g.
// what to include in the IPPT draft-ietf-dtn-bpsec-interop-sc-02#section-3.2
// Default 0x7
const (
	PrimaryBlockFlag   uint16 = 0b001
	TargetHeaderFlag   uint16 = 0b010
	SecurityHeaderFlag uint16 = 0b100
)

// BlockCodeType BlockTypeCode must return a constant integer, indicating the block type code.
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

// NewBIBIOPHMACSHA2

func NewBIBIOPHMACSHA2(shaVariant *uint64, wrappedKey *[]byte, integrityScopeFlags *uint16, securityTargets []uint64, securitySource EndpointID) *BIBIOPHMACSHA2 {

	securityContextParametersPresentFlag := uint64(0)

	if shaVariant != nil || wrappedKey != nil || integrityScopeFlags != nil {
		securityContextParametersPresentFlag = 1
	}

	var securityContextParameters []IDValueTuple

	if shaVariant != nil {
		securityContextParameters = append(securityContextParameters, &IDValueTupleUInt64{
			id:    SecParIdentBIBIOPHMACSHA2ShaVariant,
			value: *shaVariant,
		})
	}

	if wrappedKey != nil {
		securityContextParameters = append(securityContextParameters, &IDValueTupleByteString{
			id:    SecParIdentBIBIOPHMACSHA2WrappedKey,
			value: *wrappedKey,
		})
	}

	if integrityScopeFlags != nil {
		securityContextParameters = append(securityContextParameters, &IDValueTupleUInt64{
			id:    SecParIdentBIBIOPHMACSHA2IntegrityScopeFlags,
			value: uint64(*integrityScopeFlags),
		})
	}

	return &BIBIOPHMACSHA2{asb: AbstractSecurityBlock{
		securityTargets:                      securityTargets,
		securityContextID:                    SecConIdentBIBIOPHMACSHA,
		securityContextParametersPresentFlag: securityContextParametersPresentFlag,
		securitySource:                       securitySource,
		SecurityContextParameters:            securityContextParameters,
		securityResults:                      []TargetSecurityResults{},
	}}

}

// prepareIPPT constructs the "Integrity Protected Plain Text" using the process defined in bpsec-default-sc-11 3.7.
func (bib *BIBIOPHMACSHA2) prepareIPPT(b Bundle, securityTargetBlockNumber uint64, bibBlockNumber uint64) (ippt io.Writer, err error) {
	// Default Value for IntegrityScopeFlag, used if the optional security parameter is not present.
	integrityScopeFlag := uint16(7)

	securityTargetBlock, err := b.GetExtensionBlockByBlockNumber(securityTargetBlockNumber)
	if err != nil {
		return nil, err
	}

	// Find the integrity scope flag security parameter if present.
	if bib.asb.HasSecurityContextParametersPresentContextFlag() {
		for _, scp := range bib.asb.SecurityContextParameters {
			if scp.ID() == SecParIdentBIBIOPHMACSHA2IntegrityScopeFlags {
				integrityScopeFlag = uint16(scp.Value().(uint64))
			}
		}
	}

	// 1. The canonical form of the IPPT starts as the CBOR encoding of the integrity scope flag.
	if err = cboring.WriteUInt(uint64(integrityScopeFlag), ippt); err != nil {
		return nil, err
	}

	// 2. If the primary block flag of the integrity scope flags is set to 1,
	// then a canonical form of the bundle's primary block MUST be calculated
	// and the result appended to the IPPT.
	if integrityScopeFlag&PrimaryBlockFlag == PrimaryBlockFlag {
		if err = b.PrimaryBlock.MarshalCbor(ippt); err != nil {
			return nil, err
		}
	}

	// 3. If the target header flag of the integrity scope flags is set to 1,
	// then the canonical form of the block type code, block number,
	// and block processing control flags associated with the security
	// target MUST be calculated and, in that order, appended to the IPPT.
	if integrityScopeFlag&TargetHeaderFlag == TargetHeaderFlag {
		if err = cboring.WriteUInt(securityTargetBlock.TypeCode(), ippt); err != nil {
			return nil, err
		}

		if err = cboring.WriteUInt(securityTargetBlock.BlockNumber, ippt); err != nil {
			return nil, err
		}

		if err = cboring.WriteUInt(uint64(securityTargetBlock.BlockControlFlags), ippt); err != nil {
			return nil, err
		}
	}

	// 4. If the security header flag of the integrity scope flags is set to 1,
	// then the canonical form of the block type code, block number,
	// and block processing control flags associated with the  BIB MUST be calculated and,
	// in that order, appended to the IPPT.

	if integrityScopeFlag&SecurityHeaderFlag == SecurityHeaderFlag {

		if err = cboring.WriteUInt(bib.BlockCodeType(), ippt); err != nil {
			return nil, err
		}
		if err = cboring.WriteUInt(bibBlockNumber, ippt); err != nil {
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

	// 5. The canonical form of the security target block-type-specific
	// data MUST be calculated and appended to the IPPT.
	if err = GetExtensionBlockManager().WriteBlock(securityTargetBlock.Value, ippt); err != nil {
		return nil, err
	}

	return ippt, nil
}
