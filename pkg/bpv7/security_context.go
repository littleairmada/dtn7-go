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
type SecurityContext interface {

	// SecurityContextIdentifier must return a constant integer, indicating the security context identifier.
	SecurityContextIdentifier() uint64

	// SecurityContextName must return a constant string, this security context's name.
	SecurityContextName() string
}

// SHA Variant Parameter Values for BIB-HMAC-SHA2.
const (
	HMAC256SHA256 uint64 = 5
	HMAC384SHA384 uint64 = 6
	HMAC512SHA512 uint64 = 7
)

// IntegrityScopeFlags are used to show how broadly how broadly the concept of integrity is being applied, e.g.
// what to include in the IPPT draft-ietf-dtn-bpsec-interop-sc-02#section-3.2 .
const (
	PrimaryBlockFlag   uint16 = 0b001
	TargetHeaderFlag   uint16 = 0b010
	SecurityHeaderFlag uint16 = 0b100
)

// BibIopHmacShaParameters BIB-HMAC-SHA2 can be parameterized to select SHA-2 variants,
//  communicate key information, and define the scope of the IPPT. draft-ietf-dtn-bpsec-interop-sc-02#section-3.3 .
type bibIopHmacSha2Parameters struct {
	ShaVariant          *uint64
	EncapsulatedKey     *[]byte
	IntegrityScopeFlags *uint16
}

type BibIopHmacSha2 struct {
	SecurityContext
	SecurityParameters []IDValueTuple
}

func (sc *BibIopHmacSha2) SecurityContextIdentifier() uint64 {
	return SecConIdentBIBIOPHMACSHA
}

func (sc *BibIopHmacSha2) SecurityContextName() string {
	return SecConNameBIBIOPHMACSHA
}
