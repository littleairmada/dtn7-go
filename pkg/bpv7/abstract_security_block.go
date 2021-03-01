// SPDX-FileCopyrightText: 2020 Matthias Axel Kröll
// SPDX-FileCopyrightText: 2020 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package bpv7

import (
	"errors"
	"fmt"
	"io"

	"github.com/dtn7/cboring"
	"github.com/hashicorp/go-multierror"
)

// IDValueTuple is the Tuple described in BPSec 3.6 and used in SecurityContextParameters and securityResult.
type IDValueTuple struct {
	iD    uint64
	value []byte
}

// MarshalCbor writes this IDValueTuple's CBOR representation.
func (idvt *IDValueTuple) MarshalCbor(w io.Writer) error {
	if err := cboring.WriteArrayLength(2, w); err != nil {
		return err
	}

	if err := cboring.WriteUInt(idvt.iD, w); err != nil {
		return err
	}

	if err := cboring.WriteByteString(idvt.value, w); err != nil {
		return err
	}

	return nil
}

// UnmarshalCbor creates this IDValueTuples's based on a CBOR representation.
func (idvt *IDValueTuple) UnmarshalCbor(r io.Reader) error {
	if n, err := cboring.ReadArrayLength(r); err != nil {
		return err
	} else if n != 2 {
		return fmt.Errorf("SecurityBlock: IDValueTuple has %d instead of 2 elements", n)
	}

	if id, err := cboring.ReadUInt(r); err != nil {
		return err
	} else {
		idvt.iD = id
	}

	if value, err := cboring.ReadByteString(r); err != nil {
		idvt.value = value
	}

	return nil
}

// TargetSecurityResults implements the security results array described in BPSEC 3.6.
type TargetSecurityResults struct {
	securityTarget uint64
	results        []IDValueTuple
}

// MarshalCbor creates this TargetSecurityResults's CBOR representation.
func (tsr *TargetSecurityResults) MarshalCbor(w io.Writer) error {
	// Minimum length of 1 for the Security Target Block Number.
	var cborArrayLen uint64 = 1
	resultCount := uint64(len(tsr.results))
	cborArrayLen += resultCount

	if err := cboring.WriteArrayLength(cborArrayLen, w); err != nil {
		return err
	}

	if err := cboring.WriteUInt(tsr.securityTarget, w); err != nil {
		return err
	}

	for _, result := range tsr.results {
		if err := result.MarshalCbor(w); err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalCbor creates this TargetSecurityResult based on a CBOR representation.
func (tsr *TargetSecurityResults) UnmarshalCbor(r io.Reader) error {
	arrayLength, err := cboring.ReadArrayLength(r)
	if err != nil {
		return err
	} else if arrayLength != 2 {
		return fmt.Errorf("SecurityBlock: TargetSecurityResults has %d elements, instead of 2", arrayLength)
	}

	if st, err := cboring.ReadUInt(r); err != nil {
		return fmt.Errorf("TargetSecurityResults UnmarshalCbor failed: %v", err)
	} else {
		tsr.securityTarget = st
	}

	for i := uint64(0); i < arrayLength; i++ {
		idvt := IDValueTuple{}
		if err := cboring.Unmarshal(&idvt, r); err != nil {
			return fmt.Errorf("TargetSecurityResults UnmarshalCbor failed: %v", err)
		} else {
			tsr.results = append(tsr.results, idvt)
		}
	}

	return nil
}

// Sorted list of Security Context Flags.
const (
	// SecurityContextParametersPresentFlag is the bit which is set if the AbstractSecurityBlock has SecurityContextParameters.
	SecurityContextParametersPresentFlag = 0b01
)

// AbstractSecurityBlock implements the Abstract Security Block (ASB) data structure described in BPSEC 3.6.
type AbstractSecurityBlock struct {
	securityTargets           []uint64
	securityContextID         uint64
	securityContextFlags      uint64
	securitySource            EndpointID
	SecurityContextParameters []IDValueTuple
	securityResults           []TargetSecurityResults
}

// HasSecurityContextParametersPresentContextFlag interpreters the securityContextFlags for the presence of the
// SecurityContextParametersPresentField as required by BPSec 3.6.
func (asb *AbstractSecurityBlock) HasSecurityContextParametersPresentContextFlag() bool {
	return asb.securityContextFlags&SecurityContextParametersPresentFlag != 0
}

// MarshalCbor writes this AbstractSecurityBlock's CBOR representation.
func (asb *AbstractSecurityBlock) MarshalCbor(w io.Writer) error {

	// Determine block length depending on security context flags.
	var blockLen uint64 = 5

	hasSecurityContextParameterContextFlag := asb.HasSecurityContextParametersPresentContextFlag()
	if hasSecurityContextParameterContextFlag {
		blockLen++
	}

	if err := cboring.WriteArrayLength(blockLen, w); err != nil {
		return err
	}

	// SecurityTargets
	securityTargetCount := uint64(len(asb.securityTargets))
	if err := cboring.WriteArrayLength(securityTargetCount, w); err != nil {
		return err
	}

	for _, securityTarget := range asb.securityTargets {
		if err := cboring.WriteUInt(securityTarget, w); err != nil {
			return err
		}
	}

	// SecurityContextID
	if err := cboring.WriteUInt(asb.securityContextID, w); err != nil {
		return err
	}

	// SecurityContextFlags
	if err := cboring.WriteUInt(asb.securityContextFlags, w); err != nil {
		return err
	}

	// SecuritySource
	if err := asb.securitySource.MarshalCbor(w); err != nil {
		return err
	}

	// SecurityContextParameters
	if hasSecurityContextParameterContextFlag {
		parameterCount := uint64(len(asb.SecurityContextParameters))
		if err := cboring.WriteArrayLength(parameterCount, w); err != nil {
			return err
		}

		for _, securityContextParameter := range asb.SecurityContextParameters {
			if err := securityContextParameter.MarshalCbor(w); err != nil {
				return err
			}
		}
	}

	// SecurityResults
	securityTargetCountInResults := uint64(len(asb.securityResults))
	if err := cboring.WriteArrayLength(securityTargetCountInResults, w); err != nil {
		return err
	}

	for _, targetSecurityResults := range asb.securityResults {
		if err := targetSecurityResults.MarshalCbor(w); err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalCbor creates this AbstractSecurityBlock based on a CBOR representation.
func (asb *AbstractSecurityBlock) UnmarshalCbor(r io.Reader) error {
	if bl, err := cboring.ReadArrayLength(r); err != nil {
		return err
	} else if bl != 5 && bl != 6 {
		return fmt.Errorf("expected array with length 5 or 6, got %d", bl)
	}

	// SecurityTargets
	if targetCount, err := cboring.ReadArrayLength(r); err != nil {
		return err
	} else {
		for i := uint64(0); i < targetCount; i++ {
			if st, err := cboring.ReadUInt(r); err != nil {
				return err
			} else {
				asb.securityTargets = append(asb.securityTargets, st)
			}
		}
	}

	// SecurityContextID
	if scid, err := cboring.ReadUInt(r); err != nil {
		return err
	} else {
		asb.securityContextID = scid
	}

	// SecurityContextFlags
	if scf, err := cboring.ReadUInt(r); err != nil {
		return err
	} else {
		asb.securityContextFlags = scf
	}

	// SecuritySource
	if err := cboring.Unmarshal(&asb.securitySource, r); err != nil {
		return err
	}

	// SecurityContextParameters (Optional)
	// Check if SecurityContextFlag is set
	if asb.HasSecurityContextParametersPresentContextFlag() {
		arrayLength, err := cboring.ReadArrayLength(r)
		if err != nil {
			return fmt.Errorf("SecurityBlock failed to unmarshal SecurityContextParameters : %v", err)
		}
		for i := uint64(0); i < arrayLength; i++ {
			idvt := IDValueTuple{}
			if err := cboring.Unmarshal(&idvt, r); err != nil {
				return fmt.Errorf("SecurityBlock failed to unmarshal SecurityContextParameters : %v", err)
			} else {
				asb.SecurityContextParameters = append(asb.SecurityContextParameters, idvt)
			}
		}
	}

	// SecurityResults
	arrayLength, err := cboring.ReadArrayLength(r)
	if err != nil {
		return fmt.Errorf("SecurityBlock failed to unmarshal SecurityResults : %v", err)
	}
	for i := uint64(0); i < arrayLength; i++ {
		tsr := TargetSecurityResults{}
		if err := cboring.Unmarshal(&tsr, r); err != nil {
			return fmt.Errorf("SecurityBlock failed to unmarshal SecurityResults : %v", err)
		} else {
			asb.securityResults = append(asb.securityResults, tsr)
		}
	}

	return asb.CheckValid()
}

// CheckValid checks for MUST / MUST NOT constraints required by BPSEC 3.6.
func (asb *AbstractSecurityBlock) CheckValid() (errs error) {

	// SecurityTargets MUST have at least 1 entry.
	if len(asb.securityTargets) == 0 {
		errs = multierror.Append(errs, errors.New(
			"not at least 1 entry in Security Targets"))
	}

	// SecurityTargets MUST NOT have duplicate entries.
	securityTargetDuplicateExists, duplicates := func() (bool, []uint64) {
		targetAlreadyExists := map[uint64]bool{}
		var duplicateTargets []uint64

		for _, target := range asb.securityTargets {
			if targetAlreadyExists[target] {
				duplicateTargets = append(duplicateTargets, target)
			} else if !targetAlreadyExists[target] {
				targetAlreadyExists[target] = true
			}
		}

		return len(duplicateTargets) != 0, duplicateTargets
	}()

	if securityTargetDuplicateExists {
		errs = multierror.Append(errs, fmt.Errorf(
			"duplicate Security Target entries exist for block number(s): %v", duplicates))
	}

	// There MUST be one entry in SecurityTargets for each entry in SecurityResults.
	// SecurityTargets and SecurityResults ordering MUST match the results associated with the targets.
	if len(asb.securityResults) != len(asb.securityTargets) {
		errs = multierror.Append(errs, fmt.Errorf(
			"number of entries in SecurityResults and SecurityTargets is not equal #Targets: %v #TargetResultSets: %v, could not check ordering ",
			len(asb.securityTargets), len(asb.securityResults)))
	} else {
		entryOrderDoesNotMatch := func() bool {
			for i, targetSecurityResult := range asb.securityResults {
				if targetSecurityResult.securityTarget != asb.securityTargets[i] {
					return true
				}
			}
			return false
		}()

		if entryOrderDoesNotMatch {
			errs = multierror.Append(errs, errors.New(
				"ordering of Security Targets and associated Security Results does not match"))
		}

	}

	if asb.HasSecurityContextParametersPresentContextFlag() {
		if len(asb.SecurityContextParameters) == 0 {
			errs = multierror.Append(errs, errors.New(
				"security block has the Security Context Parameters Present Context Flag (0x01) set, but no Security Parameter Context Field is present"))

		}
	} else {
		if len(asb.SecurityContextParameters) != 0 {
			errs = multierror.Append(errs, errors.New(
				"security block has the Security Context Parameters Present Context Flag (0x01) not set, but the Security Parameter Context Field is present"))
		}
	}

	return errs
}
