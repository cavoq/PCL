package linter

import "time"

type Config struct {
	PolicyPath  string
	CertPath    string
	CertURLs    []string
	CertTimeout time.Duration
	CertSaveDir string
	CRLPath     string
	OCSPPath    string
	OutputFmt   string
	Verbosity   int
	ShowMeta    bool
}
