package loader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/cavoq/PCL/internal/io"
)

type ParseFunc[T any] func(data []byte) (T, error)

type RawDataFunc[T any] func(T) []byte

type Info[T any] struct {
	Data     T
	FilePath string
	Hash     string
}

func Load[T any](path string, parse ParseFunc[T]) (T, error) {
	var zero T
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}
	return parse(data)
}

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
		item, err := Load(f, parse)
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
