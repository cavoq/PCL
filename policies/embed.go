// Package policies embeds the shipped policy packs, so the pcl binary can
// evaluate them by id without the repository.
package policies

import "embed"

// FS holds every shipped policy pack (*.yaml).
//
//go:embed *.yaml
var FS embed.FS
