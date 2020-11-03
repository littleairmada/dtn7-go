// SPDX-FileCopyrightText: 2020 Matthias Axel Kröll
// SPDX-FileCopyrightText: 2020 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package bpv7

// Sorted list of all known security contexts.
const (
	// BIB-IOP-HMAC256-SHA256 as described in draft-ietf-dtn-bpsec-interop-sc-01#section-3 .
	SecConIdentBIBIOPHMAC256SHA256 uint64 = 0

	// BCB-IOP-AES-GCM-256 as described in  draft-ietf-dtn-bpsec-interop-sc-01#section-3 .
	SecConIdentBCBIOPAESGCM256 uint64 = 1
)

// SecurityContext is the canonical security context described in BPSec 2.4 .
type SecurityContext interface {

	// SecurityContextIdentifier must return a constant integer, indicating the security context identifier.
	SecurityContextIdentifier() uint64

	// SecurityContextName must return a constant string, this security context's name.
	SecurityContextName() string
}

// TODO: SC MANAGER

// TODO: IMPLEMENT SCs
