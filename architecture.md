# PCL Architecture

**Policy-based X.509 Certificate Linter** — A modular system for validating X.509 certificates against configurable YAML-based policies.

---

## Data Flow Pipeline

The system processes data through a well-defined pipeline: raw certificate data and policies are transformed into a unified representation, validated against rules, and finally formatted for presentation.

```mermaid
graph LR
    subgraph Input["📥 Input Data"]
        Certs["X.509 Certificates<br/>CRL Responses<br/>OCSP Responses"]
        Policies["YAML Policy Files<br/>Validation Rules"]
    end
    
    subgraph Transform["🔄 Transformation"]
        NodeTree["Certificate Node Tree<br/>Unified Abstraction"]
        RuleSet["Parsed Rule Set<br/>Normalized Format"]
    end
    
    subgraph Validate["✓ Validation"]
        Engine["Rule Evaluation Engine<br/>40+ Operators<br/>Field Resolution"]
    end
    
    subgraph Export["📤 Export"]
        Formatter["Output Formatter<br/>Text/JSON/YAML"]
        Results["Structured Results<br/>Pass/Fail/Skip Status"]
    end
    
    Certs -->|Parse| NodeTree
    Policies -->|Parse| RuleSet
    NodeTree -->|Feed| Engine
    RuleSet -->|Apply| Engine
    Engine -->|Generate| Formatter
    Formatter -->|Produce| Results
    
    style Input fill:#e8f4f8,stroke:#333,stroke-width:2px,color:#000
    style Transform fill:#e8f4f8,stroke:#333,stroke-width:2px,color:#000
    style Validate fill:#e8f4f8,stroke:#333,stroke-width:2px,color:#000
    style Export fill:#e8f4f8,stroke:#333,stroke-width:2px,color:#000
    style Certs fill:#ffffff,stroke:#333,stroke-width:2px,color:#000
    style Policies fill:#ffffff,stroke:#333,stroke-width:2px,color:#000
    style NodeTree fill:#ffffff,stroke:#333,stroke-width:2px,color:#000
    style RuleSet fill:#ffffff,stroke:#333,stroke-width:2px,color:#000
    style Engine fill:#ffffff,stroke:#333,stroke-width:2px,color:#000
    style Formatter fill:#ffffff,stroke:#333,stroke-width:2px,color:#000
    style Results fill:#ffffff,stroke:#333,stroke-width:2px,color:#000
```

---

## Key Components

| Component | Purpose |
|-----------|---------|
| **Data Acquisition** | Load certificates from files, directories, or HTTPS endpoints |
| **Policy Engine** | Parse YAML policies and extract validation rules |
| **Evaluation Engine** | Apply rules to certificates using a registry of 40+ operators |
| **Certificate Abstraction** | Unified node-tree representation for flexible field access |
| **Output Formatter** | Generate results in text, JSON, or YAML format |
