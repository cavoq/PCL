// Package finding defines structured validation evidence shared by domain
// decisions and output results. It contains representation only; domain
// packages own the meaning of finding codes and messages.
package finding

// Status is a stable finding outcome.
type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

// Finding is one structured validation decision. CertificateIndex uses
// target-to-anchor ordering and is -1 for path-wide findings.
type Finding struct {
	Code               string         `json:"code" yaml:"code"`
	Reference          string         `json:"reference,omitempty" yaml:"reference,omitempty"`
	Status             Status         `json:"status" yaml:"status"`
	CertificateIndex   int            `json:"certificate_index" yaml:"certificate_index"`
	CertificateSubject string         `json:"certificate_subject,omitempty" yaml:"certificate_subject,omitempty"`
	Message            string         `json:"message" yaml:"message"`
	Details            map[string]any `json:"details,omitempty" yaml:"details,omitempty"`
}
