package bpv7

import (
	"github.com/dtn7/cboring"
	"io"
)

// IDValueTuple is the Tuple described in BPSec 3.6 and used in securityContextParameters and securityResult.
type IDValueTuple struct {
	ID    uint64
	value string
}

// MarshalCbor writes this IDValueTuple's CBOR representation.
func (idvt *IDValueTuple) MarshalCbor(w io.Writer) error {
	if err := cboring.WriteArrayLength(2, w); err != nil {
		return err
	}

	if err := cboring.WriteUInt(idvt.ID, w); err != nil {
		return err
	}

	if err := cboring.WriteTextString(idvt.value, w); err != nil {
		return err
	}

	return nil
}

// UnmarshalCbor creates this IDValueTuples's based on a CBOR representation.
func (idvt *IDValueTuple) UnmarshalCbor(r io.Writer) error {
	// TODO: UnmarshalCbor for IDValueTuple
	return nil
}

// TargetSecurityResults implements the security results array described in BPSEC 3.6.
type TargetSecurityResults struct {
	results []IDValueTuple
}

// MarshalCbor creates this TargetSecurityResults's CBOR representation.
func (tsr *TargetSecurityResults) MarshalCbor(w io.Writer) error {
	resultCount := uint64(len(tsr.results))

	if err := cboring.WriteArrayLength(resultCount, w); err != nil {
		return err
	}

	for _, result := range tsr.results {
		if err := result.MarshalCbor(w); err != nil {
			return err
		}
	}
	return nil
}

// Sorted list of Security Context Flags
const (
	// SecurityContextParametersPresentFlag is the bit which is set if the AbstractSecurityBlock has SecurityContextParameters.
	SecurityContextParametersPresentFlag = 0b01

	// SecuritySourcePresentFlag is the bit which is set if the AbstractSecurityBlock has a SecuritySource.
	SecuritySourcePresentFlag = 0b10
)

// AbstractSecurityBlock implements the Abstract Security Block (ABS) data structure described in BPSEC 3.6.
type AbstractSecurityBlock struct {
	securityTargets           []uint64
	securityContextID         uint64
	securityContextFlags      uint64
	securitySource            EndpointID
	securityContextParameters []IDValueTuple
	securityResults           []TargetSecurityResults
}

// HasSecurityContextParametersContextFlag interpreters the securityContextFlags for the presence of the
// securityContextParametersField as required by BPSec 3.6.
// Does not check the real presence of a security source field, use CheckValid for this.
func (asb *AbstractSecurityBlock) HasSecurityContextParametersContextFlag() bool {
	return asb.securityContextFlags&SecurityContextParametersPresentFlag != 0
}

// HasSecuritySourceContextFlag interpreters the securityContextFlags for the presence of the securitySourceField
// as required by BPSec 3.6.
// Does not check the real presence of a security context parameter field, use CheckValid for this.
func (asb *AbstractSecurityBlock) HasSecuritySourceContextFlag() bool {
	return asb.securityContextFlags&SecuritySourcePresentFlag != 0
}

// MarshalCbor writes this AbstractSecurityBlock's CBOR representation.
func (asb *AbstractSecurityBlock) MarshalCbor(w io.Writer) error {

	// Determine block length depending on security context flags.
	var blockLen uint64 = 4

	hasSecurityContextParameterContextFlag := asb.HasSecurityContextParametersContextFlag()
	if hasSecurityContextParameterContextFlag {
		blockLen++
	}

	hasSecuritySourceContextFlag := asb.HasSecuritySourceContextFlag()
	if hasSecuritySourceContextFlag {
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
	if hasSecuritySourceContextFlag {
		if err := asb.securitySource.MarshalCbor(w); err != nil {
			return err
		}
	}

	// SecurityContextParameters
	if hasSecurityContextParameterContextFlag {
		parameterCount := uint64(len(asb.securityContextParameters))
		if err := cboring.WriteArrayLength(parameterCount, w); err != nil {
			return err
		}

		for _, securityContextParameter := range asb.securityContextParameters {
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
