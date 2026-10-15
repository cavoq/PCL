package source

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cavoq/PCL/internal/fsutil"
)

// DecodePEMOrDER decodes every PEM block of blockType in data, or data as a
// single DER item when it holds no PEM block. Other PEM block types, such as
// keys next to a certificate, are skipped.
func DecodePEMOrDER[T any](data []byte, blockType string, parse func([]byte) (T, error)) ([]T, Format, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		item, err := parse(data)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PEM or DER data: %w", err)
		}
		return []T{item}, FormatDER, nil
	}

	var items []T
	for ; block != nil; block, rest = pem.Decode(rest) {
		if block.Type != blockType {
			continue
		}
		item, err := parse(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("PEM %s block %d: %w", blockType, len(items)+1, err)
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil, "", fmt.Errorf("no %s block in PEM data", blockType)
	}
	return items, FormatPEM, nil
}

// Loaded is one item decoded from an input file.
type Loaded[T any] struct {
	Item   T
	Path   string
	Format Format
}

// LoadFiles decodes the file at path, or every file with one of extensions
// in the directory path. Files that cannot be read or decoded are reported to
// w and skipped; the load fails when no file yields an item.
func LoadFiles[T any](
	path string,
	extensions []string,
	decode func([]byte) ([]T, Format, error),
	w io.Writer,
) ([]Loaded[T], error) {
	files, err := fsutil.GetFilesWithExtensions(path, extensions...)
	if err != nil {
		return nil, err
	}

	var loaded []Loaded[T]
	var skipped []error
	for _, file := range files {
		items, format, err := decodeFile(file, decode)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("%s: %w", file, err))
			continue
		}
		for _, item := range items {
			loaded = append(loaded, Loaded[T]{Item: item, Path: file, Format: format})
		}
	}

	if len(loaded) == 0 && len(skipped) > 0 {
		return nil, fmt.Errorf("no valid items found in %s: %w", path, errors.Join(skipped...))
	}
	if w != nil {
		for _, err := range skipped {
			_, _ = fmt.Fprintf(w, "Warning: skipped %v\n", err)
		}
	}
	return loaded, nil
}

func decodeFile[T any](file string, decode func([]byte) ([]T, Format, error)) ([]T, Format, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, "", err
	}
	return decode(data)
}
