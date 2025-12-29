package loader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/cavoq/PCL/internal/io"
)

// ParseFunc is a function that parses raw file bytes into a typed result.
type ParseFunc[T any] func(path string) (T, error)

// RawDataFunc extracts raw bytes from a parsed object for hashing.
type RawDataFunc[T any] func(T) []byte

// LoadAll loads all files matching the given extensions from a path,
// parses each one, and returns a slice of Info structs.
func LoadAll[T any](
	path string,
	extensions []string,
	parse ParseFunc[T],
	rawData RawDataFunc[T],
) ([]*Info[T], error) {
	files, err := io.GetFilesWithExtensions(path, extensions...)
	if err != nil {
		return nil, err
	}

	results := make([]*Info[T], 0, len(files))
	for _, f := range files {
		item, err := parse(f)
		if err != nil {
			continue
		}

		hash := sha256.Sum256(rawData(item))
		results = append(results, &Info[T]{
			Data:     item,
			FilePath: f,
			Hash:     hex.EncodeToString(hash[:]),
		})
	}

	if len(results) == 0 && len(files) > 0 {
		return nil, fmt.Errorf("no valid items found in %s", path)
	}

	return results, nil
}

// Info holds a parsed item along with its file path and content hash.
type Info[T any] struct {
	Data     T
	FilePath string
	Hash     string
}

// Load loads a single file from disk and parses it.
func Load[T any](path string, parse func([]byte) (T, error)) (T, error) {
	var zero T
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}
	return parse(data)
}

// GetFiles returns all files matching the given extensions from a path.
func GetFiles(path string, extensions ...string) ([]string, error) {
	return io.GetFilesWithExtensions(path, extensions...)
}
