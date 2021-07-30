// SPDX-FileCopyrightText: 2020 Matthias Axel Kröll
// SPDX-FileCopyrightText: 2020 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package bpv7

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/dtn7/cboring"
	"github.com/hashicorp/go-multierror"
)

type IDValueTuple interface {
	ID() uint64
	Value() interface{}
	cboring.CborMarshaler
}

type IDValueTupleByteString struct {
	id    uint64
	value []byte
}

func (idvtbs *IDValueTupleByteString) MarshalCbor(w io.Writer) error {
	if err := cboring.WriteArrayLength(2, w); err != nil {
		return err
	}

	if err := cboring.WriteUInt(idvtbs.id, w); err != nil {
		return err
	}

	if err := cboring.WriteByteString(idvtbs.value, w); err != nil {
		return err
	}

	return nil
}

func (idvtbs *IDValueTupleByteString) UnmarshalCbor(r io.Reader) error {
	if l, err := cboring.ReadArrayLength(r); err != nil {
		return err
	} else if l != 2 {
		return fmt.Errorf("wrong array length: %d instead of 2", l)
	}

	if id, err := cboring.ReadUInt(r); err != nil {
		return err
	} else {
		idvtbs.id = id
	}

	if result, err := cboring.ReadByteString(r); err != nil {
		return err
	} else {
		idvtbs.value = result
	}

	return nil
}

func (idvtbs IDValueTupleByteString) ID() uint64 {
	return idvtbs.id
}

func (idvtbs IDValueTupleByteString) Value() interface{} {
	return idvtbs.value
}

type IDValueTupleUInt64 struct {
	id    uint64
	value uint64
}

func (idvtuint64 *IDValueTupleUInt64) MarshalCbor(w io.Writer) error {
	if err := cboring.WriteArrayLength(2, w); err != nil {
		return err
	}

	if err := cboring.WriteUInt(idvtuint64.id, w); err != nil {
		return err
	}

	if err := cboring.WriteUInt(idvtuint64.value, w); err != nil {
		return err
	}

	return nil
}

func (idvtuint64 *IDValueTupleUInt64) UnmarshalCbor(r io.Reader) error {
	if l, err := cboring.ReadArrayLength(r); err != nil {
		return err
	} else if l != 2 {
		return fmt.Errorf("wrong array length: %d instead of 3", l)
	}

	if id, err := cboring.ReadUInt(r); err != nil {
		return err
	} else {
		idvtuint64.id = id
	}

	if result, err := cboring.ReadUInt(r); err != nil {
		return err
	} else {
		idvtuint64.value = result
	}

	return nil
}

func (idvtuint64 IDValueTupleUInt64) ID() uint64 {
	return idvtuint64.id
}

func (idvtuint64 IDValueTupleUInt64) Value() interface{} {
	return idvtuint64.value
}

// TargetSecurityResults implements the security results array described in BPSEC 3.6.
type TargetSecurityResults struct {
	securityTarget uint64 // The SecurityTargets BlockNumber.
	results        []IDValueTuple
}

// MarshalCbor creates this TargetSecurityResults's CBOR representation.
func (tsr *TargetSecurityResults) MarshalCbor(w io.Writer) error {
	if err := cboring.WriteArrayLength(2, w); err != nil {
		return fmt.Errorf("TargetSecurityResults MarshalCbor failed: %v", err)
	}

	if err := cboring.WriteUInt(tsr.securityTarget, w); err != nil {
		return fmt.Errorf("TargetSecurityResults MarshalCbor failed: %v", err)
	}

	if err := cboring.WriteArrayLength(uint64(len(tsr.results)), w); err != nil {
		return fmt.Errorf("TargetSecurityResults MarshalCbor failed: %v", err)
	}
	for i := 0; i < len(tsr.results); i++ {
		if err := cboring.Marshal(tsr.results[i], w); err != nil {
			return fmt.Errorf("CanonicalBlock failed: %v", err)
		}
	}

	return nil
}

// UnmarshalCbor creates this TargetSecurityResult based on a CBOR representation and returns the reader.
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

	if resultCount, err := cboring.ReadArrayLength(r); err != nil {
		return fmt.Errorf("SecurityBlock failed to unmarshal SecurityContextParameters : %v", err)
	} else {

		for i := uint64(0); i < resultCount; i++ {
			result := IDValueTupleByteString{}
			if err := cboring.Unmarshal(&result, r); err != nil {
				return fmt.Errorf("TargetSecurityResults UnmarshalCbor failed: %v", err)
			}
			tsr.results = append(tsr.results, &result)
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
	securityTargets                      []uint64
	securityContextID                    uint64
	securityContextParametersPresentFlag uint64
	securitySource                       EndpointID
	SecurityContextParameters            []IDValueTuple
	securityResults                      []TargetSecurityResults
}

// HasSecurityContextParametersPresentContextFlag interpreters the securityContextParametersPresentFlag for the presence of the
// SecurityContextParametersPresentField as required by BPSec 3.6.
func (asb *AbstractSecurityBlock) HasSecurityContextParametersPresentContextFlag() bool {
	return asb.securityContextParametersPresentFlag&SecurityContextParametersPresentFlag != 0
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
	if err := cboring.WriteUInt(asb.securityContextParametersPresentFlag, w); err != nil {
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
		asb.securityContextParametersPresentFlag = scf
	}

	// SecuritySource
	if err := cboring.Unmarshal(&asb.securitySource, r); err != nil {
		return err
	}

	// SecurityContextParameters (Optional)
	// Check if SecurityContextFlag is set
	// SecurityContextParameters
	// Check if SecurityContextFlag is set
	if asb.HasSecurityContextParametersPresentContextFlag() {
		var err error
		r, err = asb.UnmarshalCborSecurityParameters(r)
		if err != nil {
			return fmt.Errorf("SecurityBlock failed to unmarshal SecurityContextParameters : %v", err)
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

	// CheckValid EndpointID
	if err := asb.securitySource.CheckValid(); err != nil {
		errs = multierror.Append(errs, err)
	}

	return errs
}

func (asb *AbstractSecurityBlock) UnmarshalCborSecurityParameters(r io.Reader) (rr io.Reader, err error) {
	arrayLengthParameters, err := cboring.ReadArrayLength(r)
	if err != nil {
		return nil, err
	} else if arrayLengthParameters > 3 {
		return nil, fmt.Errorf("wrong array length: %d instead of max 3", arrayLengthParameters)
	}

	bufferedReader := bufio.NewReader(r)

	for i := uint64(0); i < arrayLengthParameters; i++ {
		peekForID, _ := bufferedReader.Peek(bufferedReader.Size())
		peekReader := bytes.NewReader(peekForID)

		_, err := cboring.ReadArrayLength(peekReader)
		if err != nil {
			return nil, err
		}

		securityParameterID, _ := cboring.ReadUInt(peekReader)

		securityParameter := SecParIdentToIDValueTupleType[securityParameterID]

		if err := cboring.Unmarshal(securityParameter, bufferedReader); err != nil {
			return nil, fmt.Errorf("TargetSecurityResults UnmarshalCbor failed: %v", err)
		} else {
			asb.SecurityContextParameters = append(asb.SecurityContextParameters, securityParameter)
		}
	}

	restOfBufferedReader, _ := io.ReadAll(bufferedReader)

	rr = bytes.NewReader(restOfBufferedReader)

	return rr, nil

}
