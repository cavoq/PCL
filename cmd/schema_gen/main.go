package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/invopop/jsonschema"

	"github.com/cavoq/PCL/internal/policy"
)

func main() {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties: false,
	}

	schema := reflector.Reflect(&policy.Policy{})
	schema.Title = "PCL Policy Schema"
	schema.Description = "Schema for PCL certificate validation policies"
	schema.ID = jsonschema.ID("https://github.com/cavoq/pcl/policy-schema.json")

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile("policy-schema.json", data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing schema: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Generated policy-schema.json")
}
