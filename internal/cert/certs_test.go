package cert

import (
	"math/big"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestCertsFromInfos(t *testing.T) {
	c := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Test"},
		SerialNumber: big.NewInt(1),
	}

	tests := []struct {
		name  string
		infos []*Info
		want  int
	}{
		{name: "nil", want: 0},
		{name: "empty", infos: []*Info{}, want: 0},
		{name: "nil info", infos: []*Info{nil}, want: 0},
		{name: "nil cert", infos: []*Info{{}}, want: 0},
		{name: "one cert", infos: []*Info{{Cert: c}}, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CertsFromInfos(tt.infos)
			if len(got) != tt.want {
				t.Fatalf("CertsFromInfos() len = %d, want %d", len(got), tt.want)
			}
			if tt.want == 1 && got[0] != c {
				t.Fatal("unexpected certificate pointer")
			}
		})
	}
}
