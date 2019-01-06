package bpa

import (
	"bytes"
	"fmt"
	"testing"
)

func TestBundleApplyCRC(t *testing.T) {
	var epPrim, _ = NewEndpointID("dtn", "foo/bar")
	var creationTs = NewCreationTimestamp(DTNTimeNow(), 23)

	var primary = NewPrimaryBlock(
		BndlCFBundleDeliveryStatusReportsAreRequested,
		epPrim, epPrim, creationTs, 42000)

	var epPrev, _ = NewEndpointID("ipn", "23.42")
	var prevNode = NewPreviousNodeBlock(1, 0, epPrev)

	var payload = NewPayloadBlock(
		BlckCFBundleMustBeDeletedIfBlockCannotBeProcessed, []byte("GuMo"))

	var bundle = NewBundle(
		primary, []CanonicalBlock{prevNode, payload})

	for _, crcTest := range []CRCType{CRCNo, CRC16, CRC32, CRCNo} {
		bundle.ApplyCRC(crcTest)

		if ty := bundle.PrimaryBlock.GetCRCType(); ty != crcTest {
			t.Errorf("Bundle's primary block has wrong CRCType, %v instead of %v",
				ty, crcTest)
		}

		if !bundle.CheckCRC() {
			t.Errorf("For %v the CRC mismatchs", crcTest)
		}
	}
}

func TestBundleCbor(t *testing.T) {
	var epDest, _ = NewEndpointID("dtn", "desty")
	var epSource, _ = NewEndpointID("dtn", "gumo")
	var creationTs = NewCreationTimestamp(DTNTimeNow(), 23)

	var primary = NewPrimaryBlock(
		BndlCFBundleDeliveryStatusReportsAreRequested,
		epDest, epSource, creationTs, 42000)

	var epPrev, _ = NewEndpointID("ipn", "23.42")
	var prevNode = NewPreviousNodeBlock(23, 0, epPrev)

	var payload = NewPayloadBlock(
		BlckCFBundleMustBeDeletedIfBlockCannotBeProcessed,
		[]byte("GuMo meine Kernel"))

	bundle1 := NewBundle(
		primary, []CanonicalBlock{prevNode, payload})
	bundle1.ApplyCRC(CRC32)

	bundle1Cbor := bundle1.ToCbor()

	bundle2 := NewBundleFromCbor(bundle1Cbor)
	bundle2Cbor := bundle2.ToCbor()

	if !bytes.Equal(bundle1Cbor, bundle2Cbor) {
		t.Errorf("Cbor-Representations do not match:\n- %v\n- %v",
			bundle1Cbor, bundle2Cbor)
	}

	s1 := fmt.Sprintf("%v", bundle1)
	s2 := fmt.Sprintf("%v", bundle2)

	if s1 != s2 {
		t.Errorf("String representations do not match:%v and %v", s1, s2)
	}
}

// This function tests the serialization and deserialization of Bundles to CBOR
// et vice versa by comparing this implementation against uPCN's Python
// implementation. Thanks for this code!
//
// uPCN: https://upcn.eu/
// modified implementation dtn-bpis-12: https://github.com/geistesk/upcn-bundle7
func TestBundleUpcn(t *testing.T) {
	// Serialized CBOR, generated by `python3 -m tools.bundle7`
	var upcnBytes = []byte{
		0x9f, 0x89, 0x07, 0x19, 0x08, 0xc4, 0x01, 0x82, 0x01, 0x63, 0x47, 0x53,
		0x32, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82, 0x00, 0x00, 0x1a, 0x00,
		0x01, 0x51, 0x80, 0x42, 0xa0, 0xc5, 0x86, 0x07, 0x01, 0x00, 0x02, 0x82,
		0x01, 0x63, 0x47, 0x53, 0x34, 0x44, 0x6a, 0xc6, 0x13, 0x2a, 0x86, 0x09,
		0x02, 0x00, 0x02, 0x82, 0x18, 0x1e, 0x00, 0x44, 0xae, 0x37, 0xa0, 0xf7,
		0x86, 0x08, 0x03, 0x00, 0x02, 0x00, 0x44, 0x68, 0xfb, 0x71, 0x6e, 0x86,
		0x01, 0x00, 0x00, 0x02, 0x4c, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77,
		0x6f, 0x72, 0x6c, 0x64, 0x21, 0x44, 0xc3, 0xae, 0xc5, 0x52, 0xff}

	bndl := NewBundleFromCbor(upcnBytes)

	if !bndl.CheckCRC() {
		t.Errorf("Decoded uPCN bundle's CRC mismatches")
	}

	// Check PrimaryBlock fields
	pb := bndl.PrimaryBlock
	if ver := pb.Version; ver != dtnVersion {
		t.Errorf("Primary Block's version is not 7: %d", ver)
	}

	bcfExpected := BndlCFBundleMustNotBeFragmented |
		BndlCFBundleContainsAManifestBlock |
		BndlCFBundleDeliveryStatusReportsAreRequested |
		BndlCFStatusTimeIsRequestedInAllStatusReports
	if bcf := pb.BundleControlFlags; bcf != bcfExpected {
		t.Errorf("Primary Block's control flags mismatches: %x instead of %x",
			bcf, bcfExpected)
	}

	destExpected, _ := NewEndpointID("dtn", "GS2")
	if dest := pb.Destination; dest != destExpected {
		t.Errorf("Primary Block's destination mismatches: %v instead of %v",
			dest, destExpected)
	}

	if src := pb.SourceNode; src != DtnNone() {
		t.Errorf("Primary Block's source node is not dtn:none: %v", src)
	}

	if rprtTo := pb.ReportTo; rprtTo != DtnNone() {
		t.Errorf("Primary Block's report to is not dtn:none: %v", rprtTo)
	}

	creaTsExpected := NewCreationTimestamp(DTNTimeEpoch, 0)
	if creaTs := pb.CreationTimestamp; creaTs != creaTsExpected {
		t.Errorf("Primary Block's creation timestamp mismatches: %v instead of %v",
			creaTs, creaTsExpected)
	}

	lifeExpected := uint(24 * 60 * 60) // defined in PrimaryBlock's constructor
	if life := pb.Lifetime; life != lifeExpected {
		t.Errorf("Primary Block's lifetime mismatches: %v instead of %v",
			life, lifeExpected)
	}

	// Check Canonical Blocks
	var chkPayload, chkPreviousNode, chkHopCount, chkBundleAge bool

	for _, cb := range bndl.CanonicalBlocks {
		switch cb.BlockType {
		case blockTypePayload:
			chkPayload = true

			payloadExpected := []byte("Hello world!")
			if payload := cb.Data.([]byte); !bytes.Equal(payload, payloadExpected) {
				t.Errorf("Payload Block's payload mismatches: %v instead of %v",
					payload, payloadExpected)
			}

		case blockTypePreviousNode:
			chkPreviousNode = true

			prevExpected, _ := NewEndpointID("dtn", "GS4")
			if prev := cb.Data.(EndpointID); prev != prevExpected {
				t.Errorf("Previous Node Block's EID mismatches: %v instead of %v",
					prev, prevExpected)
			}

		case blockTypeHopCount:
			chkHopCount = true

			hopExpected := NewHopCount(30, 0)
			if hop := cb.Data.(HopCount); hop != hopExpected {
				t.Errorf("Hop Count Block mismatches: %v instead of %v",
					hop, hopExpected)
			}

		case blockTypeBundleAge:
			chkBundleAge = true

			ageExpected := uint(0)
			if age := cb.Data.(uint); age != ageExpected {
				t.Errorf("Bundle Age Block's value mismatches: %d instead of %d",
					age, ageExpected)
			}

		default:
			t.Errorf("Unexpected Canonical Block: %v", cb)
		}
	}

	if !(chkPayload && chkPreviousNode && chkHopCount && chkBundleAge) {
		t.Error("Not all expected Canonical Blocks were found")
	}

	// Serialize CBOR again
	var recreatedBytes = bndl.ToCbor()

	if !bytes.Equal(upcnBytes, recreatedBytes) {
		t.Errorf("Serialization of uPCN's bundle differs: %v instead of %v",
			upcnBytes, recreatedBytes)
	}
}

func TestBundleCheckValid(t *testing.T) {
	tests := []struct {
		b     Bundle
		valid bool
	}{
		// Administrative record
		{NewBundle(
			NewPrimaryBlock(BndlCFBundleMustNotBeFragmented|BndlCFPayloadIsAnAdministrativeRecord,
				DtnNone(), DtnNone(), NewCreationTimestamp(42, 0), 3600),
			[]CanonicalBlock{
				NewPayloadBlock(BlckCFStatusReportMustBeTransmittedIfBlockCannotBeProcessed, nil)}),
			false},

		{NewBundle(
			NewPrimaryBlock(BndlCFBundleMustNotBeFragmented|BndlCFPayloadIsAnAdministrativeRecord,
				DtnNone(), DtnNone(), NewCreationTimestamp(42, 0), 3600),
			[]CanonicalBlock{NewPayloadBlock(0, nil)}),
			true},

		// Block number (0) occures twice
		{NewBundle(
			NewPrimaryBlock(BndlCFBundleMustNotBeFragmented|BndlCFPayloadIsAnAdministrativeRecord,
				DtnNone(), DtnNone(), NewCreationTimestamp(42, 0), 3600),
			[]CanonicalBlock{
				NewPayloadBlock(0, nil), NewPayloadBlock(0, nil)}),
			false},

		// Two Hop Count blocks
		{NewBundle(
			NewPrimaryBlock(BndlCFBundleMustNotBeFragmented|BndlCFPayloadIsAnAdministrativeRecord,
				DtnNone(), DtnNone(), NewCreationTimestamp(42, 0), 3600),
			[]CanonicalBlock{
				NewHopCountBlock(23, 0, NewHopCount(23, 2)),
				NewHopCountBlock(24, 0, NewHopCount(23, 2)),
				NewPayloadBlock(0, nil)}),
			false},

		// Creation Time = 0, no Bundle Age block
		{NewBundle(
			NewPrimaryBlock(BndlCFBundleMustNotBeFragmented|BndlCFPayloadIsAnAdministrativeRecord,
				DtnNone(), DtnNone(), NewCreationTimestamp(0, 0), 3600),
			[]CanonicalBlock{
				NewBundleAgeBlock(1, 0, 42000),
				NewPayloadBlock(0, nil)}),
			true},
		{NewBundle(
			NewPrimaryBlock(BndlCFBundleMustNotBeFragmented|BndlCFPayloadIsAnAdministrativeRecord,
				DtnNone(), DtnNone(), NewCreationTimestamp(0, 0), 3600),
			[]CanonicalBlock{
				NewPayloadBlock(0, nil)}),
			false},
	}

	for _, test := range tests {
		if err := test.b.checkValid(); (err == nil) != test.valid {
			t.Errorf("Block validation failed: %v resulted in %v",
				test.b, err)
		}
	}
}
