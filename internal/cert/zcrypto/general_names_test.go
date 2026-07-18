package zcrypto

import "testing"

func TestParseGeneralNamesInfoRejectsInvalidNames(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{name: "empty GeneralNames", value: []byte{0x30, 0x00}},
		{name: "unknown choice", value: []byte{0x30, 0x02, 0x89, 0x00}},
		{name: "wrong class", value: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		{name: "empty DNS name", value: []byte{0x30, 0x02, 0x82, 0x00}},
		{name: "empty x400 address", value: []byte{0x30, 0x02, 0xa3, 0x00}},
		{name: "invalid IP length", value: []byte{0x30, 0x05, 0x87, 0x03, 0x01, 0x02, 0x03}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseGeneralNamesInfo(tt.value); err == nil {
				t.Fatal("expected invalid GeneralName to be rejected")
			}
		})
	}
}
