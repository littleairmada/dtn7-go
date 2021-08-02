package bpv7

import (
	"bytes"
	"fmt"
	"github.com/dtn7/cboring"
	"testing"
	"time"
)

func TestBIBIOPHMACSHA2_VerifyTargets(t *testing.T) {
	b, bErr := Builder().
		CRC(CRC32).
		Source("dtn://src/").
		Destination("dtn://dst/").
		CreationTimestampNow().
		Lifetime(30 * time.Minute).
		PayloadBlock([]byte("hello world")).
		Build()
	if bErr != nil {
		t.Fatal(bErr)
	}

	privateKey := "dtnislove"

	payloadSecurityTarget, _ := b.ExtensionBlock(ExtBlockTypePayloadBlock)

	securityTargets := []uint64{payloadSecurityTarget.BlockNumber}

	shaVariant := HMAC256SHA256

	bib := NewBIBIOPHMACSHA2(&shaVariant, nil, nil, securityTargets, b.PrimaryBlock.SourceNode)

	eb := CanonicalBlock{
		BlockNumber:       0,
		BlockControlFlags: 0,
		CRCType:           CRCNo,
		CRC:               nil,
		Value:             bib,
	}

	b.AddExtensionBlock(eb)

	bibBlockAdded, _ := b.ExtensionBlock(bib.BlockTypeCode())

	err := bibBlockAdded.Value.(*BIBIOPHMACSHA2).SignTargets(b, bibBlockAdded.BlockNumber, []byte(privateKey))
	if err != nil {
		return
	}

	buff := new(bytes.Buffer)
	if err := cboring.Marshal(bibBlockAdded, buff); err != nil {
		t.Fatal(err)
	}

	fmt.Println("BIB String:")
	fmt.Printf("%X\n", buff)

	fmt.Println("Bundle String:")

	buff = new(bytes.Buffer)
	if err := cboring.Marshal(&b, buff); err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%X\n", buff)


	//if !bytes.Equal(pub, sb.PublicKey) {
	//	t.Fatalf("SignatureBlock's public key %x differs from %x", sb.PublicKey, pub)
	//}
	//
	//if err := sb.CheckValid(); err != nil {
	//	t.Fatal(err)
	//}
	//
	//if !sb.Verify(b) {
	//	t.Fatal("SignatureBlock cannot be verified")
	//}
}
