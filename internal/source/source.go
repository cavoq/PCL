package source

type Type string

const (
	Local      Type = "local"
	Downloaded Type = "downloaded"
	Extracted  Type = "extracted"
)

type Format string

const (
	FormatDER   Format = "DER"
	FormatPEM   Format = "PEM"
	FormatPKCS7 Format = "PKCS7"
)

type Info struct {
	Type        Type
	URL         string
	Format      Format
	Description string
}

func (i Info) String() string {
	if i.Description != "" {
		return i.Description
	}
	return string(i.Type)
}
