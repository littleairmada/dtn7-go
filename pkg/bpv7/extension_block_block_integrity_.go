package bpv7

import "io"



// BlockIntegrityBlock implements the BPSEC Block Integrity Block (BIB)
type BlockIntegrityBlock struct {
	abstractSecurityBlock AbstractSecurityBlock
}

// BlockTypeCode must return a constant integer, indicating the block type code.
func (bib *BlockIntegrityBlock) BlockCodeType() uint64 {
	return ExtBlockTypeBlockIntegrityBlock
}

// MarshalCbor writes a CBOR representation for a Bundle Integrity Block.
func (bib *BlockIntegrityBlock) MarshalCbor(w io.Writer) error {
	return nil
}

// UnmarshalCbor writes a CBOR representation for a Bundle Integrity Block
func (bib *BlockIntegrityBlock) UnmarshalCbor(w io.Writer) error {
	return nil
}

// CheckValid returns an array of errors for incorrect data.
func (bib *BlockIntegrityBlock) CheckValid() error {
	return nil
}
