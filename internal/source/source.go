package source

type Type string

const (
	Local      Type = "local"
	Downloaded Type = "downloaded"
	Extracted  Type = "extracted"
)

type Info struct {
	Type        Type
	URL         string
	Format      string
	Description string
}

func (i Info) String() string {
	if i.Description != "" {
		return i.Description
	}
	return string(i.Type)
}
