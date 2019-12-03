package bundle

import (
	"bytes"
	"reflect"
	"testing"
)

func TestExtensionBlockManager(t *testing.T) {
	var ebm = NewExtensionBlockManager()

	payloadBlock := NewPayloadBlock(nil)
	if err := ebm.Register(payloadBlock); err != nil {
		t.Fatal(err)
	}
	if err := ebm.Register(payloadBlock); err == nil {
		t.Fatal("Registering the PayloadBlock twice did not errored")
	}

	extBlock, extBlockErr := ebm.CreateBlock(payloadBlock.BlockTypeCode())
	if extBlockErr != nil {
		t.Fatal(extBlockErr)
	}

	if extBlock.BlockTypeCode() != payloadBlock.BlockTypeCode() {
		t.Fatalf("Block type code differs: %d != %d",
			extBlock.BlockTypeCode(), payloadBlock.BlockTypeCode())
	}

	if _, err := ebm.CreateBlock(9001); err == nil {
		t.Fatal("CreateBlock for an unknown number did not result in an errored")
	}

	ebm.Unregister(payloadBlock)
	if _, err := ebm.CreateBlock(payloadBlock.BlockTypeCode()); err == nil {
		t.Fatal("CreateBlock for an unregistered number did not result in an error")
	}
}

func TestExtensionBlockManagerRWBlock(t *testing.T) {
	var ebm = GetExtensionBlockManager()

	tests := []struct {
		from     ExtensionBlock
		to       []byte
		typeCode uint64
	}{
		// With a wrapped CBOR byte string
		{NewBundleAgeBlock(23), []byte{0x41, 0x17}, ExtBlockTypeBundleAgeBlock},
		{NewHopCountBlock(16), []byte{0x43, 0x82, 0x10, 0x00}, ExtBlockTypeHopCountBlock},
		{NewPreviousNodeBlock(MustNewEndpointID("dtn:23")), []byte{0x45, 0x82, 0x01, 0x62, 0x32, 0x33}, ExtBlockTypePreviousNodeBlock},

		// Directly converted
		// TODO: add "binary" code; remove byte string bytes
		{NewGenericExtensionBlock([]byte{0xFF}, 192), []byte{0x42, 0x41, 0xFF}, 192},
		{NewPayloadBlock([]byte("lel")), []byte{0x44, 0x43, 0x6C, 0x65, 0x6C}, ExtBlockTypePayloadBlock},
	}

	for _, test := range tests {
		// Block -> Binary / CBOR
		var buff = new(bytes.Buffer)
		if err := ebm.WriteBlock(test.from, buff); err != nil {
			t.Fatal(err)
		} else if to := buff.Bytes(); !bytes.Equal(to, test.to) {
			t.Fatalf("Bytes are not equal: %x != %x", test.to, to)
		}

		// Binary / CBOR -> Block
		buff = bytes.NewBuffer(test.to)
		if b, err := ebm.ReadBlock(test.typeCode, buff); err != nil {
			t.Fatal(err)
		} else if !reflect.DeepEqual(b, test.from) {
			t.Fatalf("Blocks differ: %v %v", test.from, b)
		}
	}
}

func TestExtensionBlockManagerSingleton(t *testing.T) {
	var ebm = GetExtensionBlockManager()

	tests := []uint64{
		ExtBlockTypePayloadBlock,
		ExtBlockTypePreviousNodeBlock,
		ExtBlockTypeBundleAgeBlock,
		ExtBlockTypeHopCountBlock}

	for _, test := range tests {
		if _, err := ebm.CreateBlock(test); err != nil {
			t.Fatalf("CreateBlock failed for %d", test)
		}
	}
}

func TestExtensionBlockManagerGenericRegister(t *testing.T) {
	var ebm = NewExtensionBlockManager()
	var geb = NewGenericExtensionBlock([]byte("nope"), 192)

	if err := ebm.Register(geb); err == nil {
		t.Fatalf("Registering a GenericExtensionBlock did not errored")
	}
}
