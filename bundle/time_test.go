package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dtn7/cboring"
)

func TestDtnTime(t *testing.T) {
	var epoch DtnTime = 0
	var ttime time.Time = epoch.Time()

	if !strings.HasPrefix(ttime.String(), "2000-01-01 00:00:00") {
		t.Errorf("Time does not represent 2000-01-01, instead: %v", ttime.String())
	}

	if _, offset := ttime.Zone(); offset != 0 {
		t.Errorf("Time is not located in UTC, instead: %d", offset)
	}

	var epoch2 DtnTime = DtnTimeFromTime(ttime)
	if epoch != epoch2 {
		t.Errorf("Converting time.Time back to DtnTime diverges: %d", epoch2)
	}

	durr, _ := time.ParseDuration("48h30m")
	ttime = ttime.Add(durr)
	if epoch+((48*60+30)*60) != DtnTimeFromTime(ttime) {
		t.Errorf("Converting time.Time back to DTNTime diverges: %d", epoch2)
	}
}

func TestCreationTimestampCbor(t *testing.T) {
	tests := []struct {
		ct   CreationTimestamp
		cbor []byte
	}{
		{NewCreationTimestamp(DtnTimeEpoch, 0), []byte{0x82, 0x00, 0x00}},
		{NewCreationTimestamp(DtnTime(23), 42), []byte{0x82, 0x17, 0x18, 0x2A}},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("serialize-%v", test.ct), func(t *testing.T) {
			buff := new(bytes.Buffer)
			if err := cboring.Marshal(&test.ct, buff); err != nil {
				t.Fatal(err)
			}

			if data := buff.Bytes(); !reflect.DeepEqual(data, test.cbor) {
				t.Fatalf("Serialization failed: %v != %v", data, test.cbor)
			}
		})

		t.Run(fmt.Sprintf("deserialize-%v", test.ct), func(t *testing.T) {
			ct := CreationTimestamp{}
			if err := cboring.Unmarshal(&ct, bytes.NewBuffer(test.cbor)); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(ct, test.ct) {
				t.Fatalf("Deserialization failed: %v != %v", ct, test.ct)
			}
		})
	}
}

func TestCreationTimestampJson(t *testing.T) {
	tests := []struct {
		ct        CreationTimestamp
		jsonBytes []byte
	}{
		{NewCreationTimestamp(DtnTimeEpoch, 0), []byte(`{"date":"2000-01-01 00:00:00","sequenceNo":0}`)},
		{NewCreationTimestamp(DtnTime(631152000), 42), []byte(`{"date":"2020-01-01 00:00:00","sequenceNo":42}`)},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("serialize-%v", test.ct), func(t *testing.T) {
			if jsonBytes, err := json.Marshal(test.ct); err != nil {
				t.Fatal(err)
			} else if !bytes.Equal(test.jsonBytes, jsonBytes) {
				t.Fatalf("expected %s, got %s", test.jsonBytes, jsonBytes)
			}
		})
	}
}
