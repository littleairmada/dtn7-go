// SPDX-FileCopyrightText: 2021 Matthias Axel Kröll
// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package bpv7

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/dtn7/cboring"
)

var _ IDValueTuple = &DummyIDValueTuple{}

func TestAbstractSecurityBlock_CheckValid(t *testing.T) {
	ep, _ := NewEndpointID("dtn://test/")

	type fields struct {
		securityTargets           []uint64
		securityContextID         uint64
		securityContextFlags      uint64
		securitySource            EndpointID
		SecurityContextParameters []IDValueTuple
		securityResults           []TargetSecurityResults
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"a valid minimal ASB, should not error", fields{
			securityTargets:      []uint64{0},
			securityContextID:    0,
			securityContextFlags: 0x1,
			securitySource:       ep,
			SecurityContextParameters: []IDValueTuple{&DummyIDValueTuple{

				value: []byte{0, 0, 0, 0, 0},
			}},
			securityResults: []TargetSecurityResults{{
				securityTarget: 0,
				results: []IDValueTuple{&DummyIDValueTuple{
					id:    0,
					value: []byte{0, 0, 0, 0, 0},
				}},
			}},
		}, false},
		{"a valid ASB, should not error", fields{
			securityTargets:      []uint64{0, 1, 2},
			securityContextID:    0,
			securityContextFlags: 0x1,
			securitySource:       ep,
			SecurityContextParameters: []IDValueTuple{
				&DummyIDValueTuple{
					id:    0,
					value: []byte{0, 0, 0, 0, 0},
				},
				&DummyIDValueTuple{
					id:    1,
					value: []byte{0, 0, 0, 0, 0},
				},
				&DummyIDValueTuple{
					id:    3,
					value: []byte{0, 0, 0, 0, 0},
				},
			},
			securityResults: []TargetSecurityResults{
				{
					securityTarget: 0,
					results: []IDValueTuple{
						&DummyIDValueTuple{
							id:    0,
							value: []byte{0, 0, 0, 0, 0},
						},
						&DummyIDValueTuple{
							id:    1,
							value: []byte{0, 0, 0, 0, 0},
						},
					},
				},
				{
					securityTarget: 1,
					results: []IDValueTuple{
						&DummyIDValueTuple{
							id:    0,
							value: []byte{0, 0, 0, 0, 0},
						},
						&DummyIDValueTuple{
							id:    1,
							value: []byte{0, 0, 0, 0, 0},
						},
					},
				},
				{
					securityTarget: 2,
					results: []IDValueTuple{
						&DummyIDValueTuple{
							id:    0,
							value: []byte{0, 0, 0, 0, 0},
						},
						&DummyIDValueTuple{
							id:    1,
							value: []byte{0, 0, 0, 0, 0},
						},
					},
				},
			},
		}, false},
		{"not at least 1 entry in Security Targets, should error", fields{
			securityTargets:      []uint64{},
			securityContextID:    0,
			securityContextFlags: 0x1,
			securitySource:       ep,
			SecurityContextParameters: []IDValueTuple{&DummyIDValueTuple{
				id:    0,
				value: []byte{0, 0, 0, 0, 0},
			}},
			securityResults: []TargetSecurityResults{{
				securityTarget: 0,
				results: []IDValueTuple{&DummyIDValueTuple{
					id:    0,
					value: []byte{0, 0, 0, 0, 0},
				}},
			}},
		}, true},
		{"duplicate Security Target entries exist, should error", fields{
			securityTargets:      []uint64{0, 0},
			securityContextID:    0,
			securityContextFlags: 0x1,
			securitySource:       ep,
			SecurityContextParameters: []IDValueTuple{&DummyIDValueTuple{
				id:    0,
				value: []byte{0, 0, 0, 0, 0},
			}},
			securityResults: []TargetSecurityResults{
				{
					securityTarget: 0,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
				{
					securityTarget: 0,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
			},
		}, true},
		{"number of entries in SecurityResults and SecurityTargets is not equal, should error", fields{
			securityTargets:      []uint64{0, 1, 2},
			securityContextID:    0,
			securityContextFlags: 0x1,
			securitySource:       ep,
			SecurityContextParameters: []IDValueTuple{&DummyIDValueTuple{
				id:    0,
				value: []byte{0, 0, 0, 0, 0},
			}},
			securityResults: []TargetSecurityResults{
				{
					securityTarget: 0,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
				{
					securityTarget: 1,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
			},
		}, true},
		{"ordering of Security Targets and associated Security Results does not match, should error", fields{
			securityTargets:      []uint64{0, 1, 2},
			securityContextID:    0,
			securityContextFlags: 0x1,
			securitySource:       ep,
			SecurityContextParameters: []IDValueTuple{&DummyIDValueTuple{
				id:    0,
				value: []byte{0, 0, 0, 0, 0},
			}},
			securityResults: []TargetSecurityResults{
				{
					securityTarget: 0,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
				{
					securityTarget: 2,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
				{
					securityTarget: 1,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
			},
		}, true},
		{"Parameters Present Context Flag set, but no Security Parameter Context Field is present, should error", fields{
			securityTargets:      []uint64{0, 1},
			securityContextID:    0,
			securityContextFlags: 0x0,
			securitySource:       ep,
			SecurityContextParameters: []IDValueTuple{&DummyIDValueTuple{
				id:    0,
				value: []byte{0, 0, 0, 0, 0},
			}},
			securityResults: []TargetSecurityResults{
				{
					securityTarget: 0,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
				{
					securityTarget: 1,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
			},
		}, true},
		{"Parameters Present Context Flag set, but no Security Parameter Context Field is present, should error", fields{
			securityTargets:           []uint64{0, 1},
			securityContextID:         0,
			securityContextFlags:      0x1,
			securitySource:            ep,
			SecurityContextParameters: []IDValueTuple{},
			securityResults: []TargetSecurityResults{
				{
					securityTarget: 0,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
				{
					securityTarget: 1,
					results: []IDValueTuple{&DummyIDValueTuple{
						id:    0,
						value: []byte{0, 0, 0, 0, 0},
					},
					},
				},
			},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asb := &AbstractSecurityBlock{
				securityTargets:           tt.fields.securityTargets,
				securityContextID:         tt.fields.securityContextID,
				securityContextFlags:      tt.fields.securityContextFlags,
				securitySource:            tt.fields.securitySource,
				SecurityContextParameters: tt.fields.SecurityContextParameters,
				securityResults:           tt.fields.securityResults,
			}
			if err := asb.CheckValid(); (err != nil) != tt.wantErr {
				t.Errorf("CheckValid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAbstractSecurityBlock_HasSecurityContextParametersPresentContextFlag(t *testing.T) {
	ep, _ := NewEndpointID("dtn://test/")
	type fields struct {
		securityTargets           []uint64
		securityContextID         uint64
		securityContextFlags      uint64
		securitySource            EndpointID
		SecurityContextParameters []IDValueTuple
		securityResults           []TargetSecurityResults
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{"flag present", fields{
			securityTargets:      []uint64{0},
			securityContextID:    0,
			securityContextFlags: 0x1,
			securitySource:       ep,
			SecurityContextParameters: []IDValueTuple{&DummyIDValueTuple{
				id:    0,
				value: []byte{0, 0, 0, 0, 0},
			}},
			securityResults: []TargetSecurityResults{{
				securityTarget: 0,
				results: []IDValueTuple{&DummyIDValueTuple{
					id:    0,
					value: []byte{0, 0, 0, 0, 0},
				}},
			}},
		}, true},
		{"flag NOT present", fields{
			securityTargets:           []uint64{0},
			securityContextID:         0,
			securityContextFlags:      0x0,
			securitySource:            ep,
			SecurityContextParameters: []IDValueTuple{},
			securityResults: []TargetSecurityResults{{
				securityTarget: 0,
				results: []IDValueTuple{&DummyIDValueTuple{
					id:    0,
					value: []byte{0, 0, 0, 0, 0},
				}},
			}},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asb := &AbstractSecurityBlock{
				securityTargets:           tt.fields.securityTargets,
				securityContextID:         tt.fields.securityContextID,
				securityContextFlags:      tt.fields.securityContextFlags,
				securitySource:            tt.fields.securitySource,
				SecurityContextParameters: tt.fields.SecurityContextParameters,
				securityResults:           tt.fields.securityResults,
			}
			if got := asb.HasSecurityContextParametersPresentContextFlag(); got != tt.want {
				t.Errorf("HasSecurityContextParametersPresentContextFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIDValueTupleCbor(t *testing.T) {
	tests := []struct {
		idVT1 DummyIDValueTuple
	}{
		{DummyIDValueTuple{
			id:    1,
			value: []byte{37, 35, 92, 90, 54},
		}},
		{DummyIDValueTuple{
			id:    1,
			value: []byte{0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00},
		}},
	}

	for _, test := range tests {
		buff := new(bytes.Buffer)
		if err := cboring.Marshal(&test.idVT1, buff); err != nil {
			t.Fatal(err)
		}
		println(buff)

		idVT2 := DummyIDValueTuple{}
		if err := cboring.Unmarshal(&idVT2, buff); err != nil {
			t.Fatalf("CBOR decoding failed: %v", err)
		}

		println(idVT2.id)
		if !reflect.DeepEqual(test.idVT1, idVT2) {
			t.Fatalf("ID Value Tuples differ:\n%v\n%v", test.idVT1, idVT2)
		}
	}
}

func TestTargetSecurityResultsCbor(t *testing.T) {
	tests := []struct {
		tsr1 TargetSecurityResults
	}{
		{TargetSecurityResults{
			securityTarget: 1,
			results: []IDValueTuple{
				&DummyIDValueTuple{
					typeCode: DummyIDVT,
					id:       0,
					value:    []byte{37, 35, 92, 90, 54},
				},
				&DummyIDValueTuple{
					typeCode: DummyIDVT,
					id:       1,
					value:    []byte{0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00},
				},
			},
		}},
		{TargetSecurityResults{
			securityTarget: 3,
			results: []IDValueTuple{
				&DummyIDValueTuple{
					typeCode: DummyIDVT,
					id:       0,
					value:    []byte{37, 35, 92, 90, 54},
				},
				&DummyIDValueTuple{
					typeCode: DummyIDVT,
					id:       1,
					value:    []byte{0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00},
				},
				&DummyIDValueTuple{
					typeCode: DummyIDVT,
					id:       2,
					value:    []byte{0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00},
				},
			},
		}},
	}

	for _, test := range tests {
		buff := new(bytes.Buffer)
		if err := cboring.Marshal(&test.tsr1, buff); err != nil {
			t.Fatal(err)
		}

		tsr2 := TargetSecurityResults{}

		if err := cboring.Unmarshal(&tsr2, buff); err != nil {
			t.Fatalf("CBOR decoding failed: %v", err)
		}

		if !reflect.DeepEqual(test.tsr1, tsr2) {
			t.Fatalf("Target Security Resluts differ:\n%v\n%v", test.tsr1, tsr2)
		}
	}
}

func TestAbstractSecurityBlockCbor(t *testing.T) {
	ep, _ := NewEndpointID("dtn://test/")
	tests := []struct {
		abs1 AbstractSecurityBlock
	}{
		{
			AbstractSecurityBlock{
				securityTargets:      []uint64{0},
				securityContextID:    0,
				securityContextFlags: 0x1,
				securitySource:       ep,
				SecurityContextParameters: []IDValueTuple{&DummyIDValueTuple{
					typeCode: DummyIDVT,
					id:       0,
					value:    []byte{37, 35, 92, 90, 54},
				}},
				securityResults: []TargetSecurityResults{{
					securityTarget: 0,
					results: []IDValueTuple{&DummyIDValueTuple{
						typeCode: DummyIDVT,
						id:       0,
						value:    []byte{37, 35, 92, 90, 54, 37, 35, 92, 90, 54},
					}},
				}},
			},
		},
		{
			AbstractSecurityBlock{
				securityTargets:           []uint64{0, 1, 2},
				securityContextID:         0,
				securityContextFlags:      0x0,
				securitySource:            ep,
				SecurityContextParameters: nil,
				securityResults: []TargetSecurityResults{
					{
						securityTarget: 0,
						results: []IDValueTuple{
							&DummyIDValueTuple{
								typeCode: DummyIDVT,
								id:       0,
								value:    []byte{37, 35, 92, 90, 54},
							},
							&DummyIDValueTuple{
								typeCode: DummyIDVT,
								id:       1,
								value:    []byte{37, 35, 92, 90, 54, 37, 35, 92, 90, 54},
							},
						},
					},
					{
						securityTarget: 1,
						results: []IDValueTuple{
							&DummyIDValueTuple{
								typeCode: DummyIDVT,

								id:    0,
								value: []byte{37, 35, 92, 90, 54, 37, 35, 92, 90, 54},
							},
							&DummyIDValueTuple{
								typeCode: DummyIDVT,

								id:    1,
								value: []byte{0, 0, 0, 0, 0, 37, 35, 92, 90, 54, 37, 35, 92, 90, 54},
							},
						},
					},
					{
						securityTarget: 2,
						results: []IDValueTuple{
							&DummyIDValueTuple{
								typeCode: DummyIDVT,

								id:    0,
								value: []byte{37, 35, 92, 90, 54, 37, 35, 92, 90, 54, 0, 0, 0, 0, 0},
							},
							&DummyIDValueTuple{
								typeCode: DummyIDVT,

								id:    1,
								value: []byte{0, 0, 37, 35, 92, 90, 54, 37, 35, 92, 90, 54, 0, 0, 0},
							},
						},
					},
				},
			},
		},
		//{
		//	AbstractSecurityBlock{
		//		securityTargets:           []uint64{0, 1, 2},
		//		securityContextID:         0,
		//		securityContextFlags:      0x0,
		//		securitySource:            ep,
		//		SecurityContextParameters: []IDValueTuple{},
		//		securityResults: []TargetSecurityResults{
		//			{
		//				securityTarget: 0,
		//				results: []IDValueTuple{
		//					&DummyIDValueTuple{
		//						typeCode: DummyIDVT,
		//						id:    0,
		//						value: []byte{37, 35, 92, 90, 54},
		//					},
		//					&DummyIDValueTuple{
		//						typeCode: DummyIDVT,
		//						id:    1,
		//						value: []byte{37, 35, 92, 90, 54, 37, 35, 92, 90, 54},
		//					},
		//				},
		//			},
		//			{
		//				securityTarget: 1,
		//				results: []IDValueTuple{
		//					&DummyIDValueTuple{
		//						typeCode: DummyIDVT,
		//
		//						id:    0,
		//						value: []byte{37, 35, 92, 90, 54, 37, 35, 92, 90, 54},
		//					},
		//					&DummyIDValueTuple{
		//						typeCode: DummyIDVT,
		//						id:       1,
		//						value:    []byte{0, 0, 0, 0, 0, 37, 35, 92, 90, 54, 37, 35, 92, 90, 54},
		//					},
		//				},
		//			},
		//			{
		//				securityTarget: 2,
		//				results: []IDValueTuple{
		//					&DummyIDValueTuple{
		//						typeCode: DummyIDVT,
		//
		//						id:    0,
		//						value: []byte{37, 35, 92, 90, 54, 37, 35, 92, 90, 54, 0, 0, 0, 0, 0},
		//					},
		//					&DummyIDValueTuple{
		//						typeCode: DummyIDVT,
		//						id:       1,
		//						value:    []byte{0, 0, 37, 35, 92, 90, 54, 37, 35, 92, 90, 54, 0, 0, 0},
		//					},
		//				},
		//			},
		//		},
		//	},
		//},
	}

	for _, test := range tests {
		buff := new(bytes.Buffer)
		if err := cboring.Marshal(&test.abs1, buff); err != nil {
			t.Fatal(err)
		}

		abs2 := AbstractSecurityBlock{}
		if err := cboring.Unmarshal(&abs2, buff); err != nil {
			t.Fatalf("CBOR decoding failed: %v", err)
		}

		if !reflect.DeepEqual(test.abs1, abs2) {
			t.Fatalf("Abstract Security Blocs differ:\n%v\n%v", test.abs1, abs2)
		}
	}
}
