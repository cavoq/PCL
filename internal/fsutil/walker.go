// Package fsutil provides filesystem walker utilities.
package fsutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func GetFilesWithExtensions(path string, extensions ...string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot access path %s: %w", path, err)
	}

	extSet := make(map[string]bool, len(extensions))
	for _, ext := range extensions {
		extSet[ext] = true
	}

	var files []string

	if info.IsDir() {
		err := filepath.Walk(path, func(p string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if fi.IsDir() {
				return nil
			}
			if extSet[filepath.Ext(p)] {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		files = append(files, path)
	}

	return files, nil
}

// ReportSkipped writes a warning to w for each input file that was skipped
// because it could not be read or parsed. A nil w discards the warnings.
func ReportSkipped(w io.Writer, skipped []error) {
	if w == nil {
		return
	}
	for _, err := range skipped {
		_, _ = fmt.Fprintf(w, "Warning: skipped %v\n", err)
	}
}
