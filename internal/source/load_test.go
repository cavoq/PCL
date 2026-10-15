package source

import (
	"bytes"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// parseWord accepts DER-like data that starts with "ok" as an item.
func parseWord(data []byte) (string, error) {
	if !bytes.HasPrefix(data, []byte("ok")) {
		return "", errors.New("not ok")
	}
	return string(data), nil
}

func decodeWords(data []byte) ([]string, Format, error) {
	return DecodePEMOrDER(data, "WORD", parseWord)
}

func pemBlock(blockType, content string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: []byte(content)})
}

func TestDecodePEMOrDER(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []string
		format  Format
		wantErr string
	}{
		{name: "DER", data: []byte("ok-der"), want: []string{"ok-der"}, format: FormatDER},
		{name: "DER that does not parse", data: []byte("bad"), wantErr: "PEM or DER"},
		{
			name:   "every block of the type",
			data:   append(pemBlock("WORD", "ok-1"), pemBlock("WORD", "ok-2")...),
			want:   []string{"ok-1", "ok-2"},
			format: FormatPEM,
		},
		{
			name:   "other block types are skipped",
			data:   append(pemBlock("KEY", "secret"), pemBlock("WORD", "ok-1")...),
			want:   []string{"ok-1"},
			format: FormatPEM,
		},
		{name: "malformed block", data: append(pemBlock("WORD", "ok-1"), pemBlock("WORD", "bad")...), wantErr: "PEM WORD block 2"},
		{name: "no block of the type", data: pemBlock("KEY", "secret"), wantErr: "no WORD block"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, format, err := decodeWords(tt.data)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || !slices.Equal(got, tt.want) || format != tt.format {
				t.Fatalf("DecodePEMOrDER() = %v, %s, %v; want %v, %s", got, format, err, tt.want, tt.format)
			}
		})
	}
}

func TestLoadFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]byte{
		"a.der":      []byte("ok-a"),
		"b.pem":      append(pemBlock("WORD", "ok-b1"), pemBlock("WORD", "ok-b2")...),
		"broken.der": []byte("bad"),
		"notes.txt":  []byte("ok-ignored"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	extensions := []string{".der", ".pem"}

	var warnings bytes.Buffer
	loaded, err := LoadFiles(dir, extensions, decodeWords, &warnings)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, item := range loaded {
		got = append(got, item.Item+"@"+filepath.Base(item.Path)+"/"+string(item.Format))
	}
	slices.Sort(got)
	want := []string{"ok-a@a.der/DER", "ok-b1@b.pem/PEM", "ok-b2@b.pem/PEM"}
	if !slices.Equal(got, want) {
		t.Fatalf("loaded = %v, want %v", got, want)
	}
	if !strings.Contains(warnings.String(), "Warning: skipped "+filepath.Join(dir, "broken.der")) || strings.Contains(warnings.String(), "notes.txt") {
		t.Fatalf("warnings = %q, want only broken.der", warnings.String())
	}

	single, err := LoadFiles(filepath.Join(dir, "a.der"), extensions, decodeWords, nil)
	if err != nil || len(single) != 1 {
		t.Fatalf("single file: %d items, %v", len(single), err)
	}
	if _, err := LoadFiles(filepath.Join(dir, "broken.der"), extensions, decodeWords, nil); err == nil || !strings.Contains(err.Error(), "no valid items") {
		t.Fatalf("broken single file: error = %v", err)
	}
	if _, err := LoadFiles(filepath.Join(dir, "missing"), extensions, decodeWords, nil); err == nil {
		t.Fatal("missing path: no error")
	}
}
