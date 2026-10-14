package x509ext

import (
	"slices"

	"github.com/zmap/zcrypto/x509/pkix"
)

// ExtensionIndex provides immutable, constant-time lookup over an ordered set
// of X.509 extensions. Duplicate extensions remain in their original order and
// are reported by Lookup rather than silently selecting one.
type ExtensionIndex struct {
	extensions []pkix.Extension
	byOID      map[string]extensionLocation
}

type extensionLocation struct {
	first int
	count int
}

// ExtensionMatch describes the presence of one extension identifier.
// Extension returns a value only when exactly one matching extension exists.
type ExtensionMatch struct {
	extension pkix.Extension
	count     int
}

// NewExtensionIndex indexes extensions by dotted-decimal object identifier
// while retaining a private copy in source order.
func NewExtensionIndex(extensions []pkix.Extension) ExtensionIndex {
	index := ExtensionIndex{
		extensions: cloneExtensions(extensions),
		byOID:      make(map[string]extensionLocation, len(extensions)),
	}
	for position, extension := range index.extensions {
		identifier := extension.Id.String()
		location, present := index.byOID[identifier]
		if !present {
			location.first = position
		}
		location.count++
		index.byOID[identifier] = location
	}
	return index
}

// Lookup reports whether identifier is absent, unique, or duplicated.
func (index ExtensionIndex) Lookup(identifier string) ExtensionMatch {
	location, present := index.byOID[identifier]
	if !present {
		return ExtensionMatch{}
	}
	return ExtensionMatch{
		extension: index.extensions[location.first],
		count:     location.count,
	}
}

// Extensions returns a copy of the indexed extensions in source order.
func (index ExtensionIndex) Extensions() []pkix.Extension {
	return cloneExtensions(index.extensions)
}

// Present reports whether at least one matching extension exists.
func (match ExtensionMatch) Present() bool {
	return match.count > 0
}

// Unique reports whether exactly one matching extension exists.
func (match ExtensionMatch) Unique() bool {
	return match.count == 1
}

// Count returns the number of matching extensions.
func (match ExtensionMatch) Count() int {
	return match.count
}

// First returns a copy of the first matching extension when at least one is
// present. Callers should normally use Extension, which rejects duplicates.
// First exists for diagnostic projections that deliberately preserve the first
// encoded instance while separately reporting duplicate OIDs.
func (match ExtensionMatch) First() (pkix.Extension, bool) {
	if !match.Present() {
		return pkix.Extension{}, false
	}
	return cloneExtension(match.extension), true
}

// Extension returns a copy of the matching extension when it is unique.
func (match ExtensionMatch) Extension() (pkix.Extension, bool) {
	if !match.Unique() {
		return pkix.Extension{}, false
	}
	return cloneExtension(match.extension), true
}

func cloneExtensions(extensions []pkix.Extension) []pkix.Extension {
	if extensions == nil {
		return nil
	}
	cloned := make([]pkix.Extension, len(extensions))
	for index, extension := range extensions {
		cloned[index] = cloneExtension(extension)
	}
	return cloned
}

func cloneExtension(extension pkix.Extension) pkix.Extension {
	extension.Id = slices.Clone(extension.Id)
	extension.Value = slices.Clone(extension.Value)
	return extension
}
