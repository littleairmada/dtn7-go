package agent

import (
	"io"

	"github.com/dtn7/cboring"
	"github.com/dtn7/dtn7-go/bundle"
)

// wamStatus is a webAgentMessage to acknowledge a previous message or report an error with a non-empty string.
// This message might be initiated from both a client or a server.
type wamStatus struct {
	errorMsg string
}

// newStatusMessage creates a new wamStatus webAgentMessage.
func newStatusMessage(err error) *wamStatus {
	if err == nil {
		return &wamStatus{""}
	} else {
		return &wamStatus{err.Error()}
	}
}

func (_ *wamStatus) typeCode() uint64 {
	return wamStatusCode
}

func (ws *wamStatus) MarshalCbor(w io.Writer) error {
	return cboring.WriteTextString(ws.errorMsg, w)
}

func (ws *wamStatus) UnmarshalCbor(r io.Reader) (err error) {
	ws.errorMsg, err = cboring.ReadTextString(r)
	return
}

// wamRegister is a webAgentMessage sent from a client to the server to register itself for an endpoint.
type wamRegister struct {
	endpoint string
}

// newRegisterMessage creates a new wamRegister webAgentMessage.
func newRegisterMessage(endpoint string) *wamRegister {
	return &wamRegister{endpoint}
}

func (_ *wamRegister) typeCode() uint64 {
	return wamRegisterCode
}

func (wr *wamRegister) MarshalCbor(w io.Writer) error {
	return cboring.WriteTextString(wr.endpoint, w)
}

func (wr *wamRegister) UnmarshalCbor(r io.Reader) (err error) {
	wr.endpoint, err = cboring.ReadTextString(r)
	return
}

// wamBundle is a webAgentMessage for sending a Bundle to a peer.
// This message might be initiated from both a client or a server.
type wamBundle struct {
	b bundle.Bundle
}

// newBundleMessage creates a new wamBundle webAgentMessage.
func newBundleMessage(b bundle.Bundle) *wamBundle {
	return &wamBundle{b}
}

func (_ *wamBundle) typeCode() uint64 {
	return wamBundleCode
}

func (wb *wamBundle) MarshalCbor(w io.Writer) error {
	return cboring.Marshal(&wb.b, w)
}

func (wb *wamBundle) UnmarshalCbor(r io.Reader) error {
	return cboring.Unmarshal(&wb.b, r)
}
