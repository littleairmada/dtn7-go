// SPDX-FileCopyrightText: 2020 Matthias Axel Kröll
// SPDX-FileCopyrightText: 2020 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package bpv7

// Sorted list of all known security contexts identifiers.
const (
	// BIB-IOP-HMAC-SHA as described in draft-ietf-dtn-bpsec-interop-sc-01#section-3 .
	SecConIdentBIBIOPHMACSHA uint64 = 0

	// BCB-IOP-AES-GCM-256 as described in  draft-ietf-dtn-bpsec-interop-sc-01#section-3 .
	SecConIdentBCBIOPAESGCM uint64 = 1
)

// Sorted list of all known security context names.
const (
	// BIB-IOP-HMAC-SHA as described in draft-ietf-dtn-bpsec-interop-sc-01#section-3 .
	SecConNameBIBIOPHMACSHA string = "BIB-HMAC-SHA2"

	// BCB-IOP-AES-GCM as described in  draft-ietf-dtn-bpsec-interop-sc-01#section-3 .
	SecConNameBCBIOPAESGCM string = "BCB-IOP-AES-GCM"
)

// SecurityContext is the canonical security context described in BPSec 2.4 .
type SecurityContext struct {

	// SecurityContextIdentifier indicating the security context identifier.
	SecurityContextIdentifier uint64

	// SecurityContextName  this security context's name.
	SecurityContextName string

	// SecurityContextParameters this security contexts parameters.
	SecurityContextParameters []IDValueTuple
}

var SecParIdentToIDValueTupleType = map[uint64]IDValueTuple{
	SecParIdentBIBIOPHMACSHA2ShaVariant:          new(IDValueTupleUInt64),
	SecParIdentBIBIOPHMACSHA2EncapsulatedKey:     new(IDValueTupleByteString),
	SecParIdentBIBIOPHMACSHA2IntegrityScopeFlags: new(IDValueTupleUInt64),
}

// BIB-HMAC-SHA2 Security Parameters
const (
	SecParIdentBIBIOPHMACSHA2ShaVariant uint64 = 1

	SecParIdentBIBIOPHMACSHA2EncapsulatedKey uint64 = 2

	SecParIdentBIBIOPHMACSHA2IntegrityScopeFlags uint64 = 3
)

//  BIB-IOP-HMAC-SHA2 ResultID
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

// BibIopHmacShaParameters BIB-HMAC-SHA2 can be parameterized to select SHA-2 variants,
//  communicate key information, and define the scope of the IPPT. draft-ietf-dtn-bpsec-interop-sc-02#section-3.3 .
type BIBIOPHMACSHA2Parameters struct {
	ShaVariant          *uint64
	EncapsulatedKey     *[]byte
	IntegrityScopeFlags *uint16 // Default 0b111
}

func NewBIPIOPHMACSHA2(securityContextParameters BIBIOPHMACSHA2Parameters) SecurityContext {

	bipiophmacsha2 := SecurityContext{
		SecurityContextIdentifier: SecConIdentBIBIOPHMACSHA,
		SecurityContextName:       SecConNameBIBIOPHMACSHA,
		SecurityContextParameters: []IDValueTuple{},
	}

	shaVariant := IDValueTupleUInt64{id: SecParIdentBIBIOPHMACSHA2ShaVariant}

	if securityContextParameters.ShaVariant != nil {
		shaVariant.value = *securityContextParameters.ShaVariant
	} else {
		shaVariant.value = HMAC256SHA256
	}

	bipiophmacsha2.SecurityContextParameters = append(bipiophmacsha2.SecurityContextParameters, &shaVariant)

	encapsulatedKey := IDValueTupleByteString{
		id: SecParIdentBIBIOPHMACSHA2EncapsulatedKey,
	}
	if securityContextParameters.EncapsulatedKey != nil {
		encapsulatedKey.value = *securityContextParameters.EncapsulatedKey
	}

	integrityScopeFlags := IDValueTupleUInt64{
		id: SecParIdentBIBIOPHMACSHA2IntegrityScopeFlags,
	}

	if securityContextParameters.IntegrityScopeFlags != nil {
		integrityScopeFlags.value = uint64(*securityContextParameters.IntegrityScopeFlags)
	} else {
		integrityScopeFlags.value = uint64(PrimaryBlockFlag + TargetHeaderFlag + SecurityHeaderFlag)
	}

	bipiophmacsha2.SecurityContextParameters = append(bipiophmacsha2.SecurityContextParameters, &shaVariant)

	return bipiophmacsha2
}
