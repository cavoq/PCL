package main

import (
	"fmt"
	"log"

	"github.com/cavoq/RCV/internal/policy"
	"gopkg.in/yaml.v3"
)

func main() {
	dir := "policies/BSI-TR-03116-TS"

	policies, err := policy.LoadPolicies(dir)
	if err != nil {
		log.Fatalf("failed to load policies: %v", err)
	}

	for name, pol := range policies {
		fmt.Printf("Policy file: %s\n", name)
		out, err := yaml.Marshal(pol)
		if err != nil {
			log.Fatalf("failed to marshal policy: %v", err)
		}
		fmt.Printf("%s\n\n", out)
	}
}
