package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
)

func TestPathLenValidName(t *testing.T) {
	op := PathLenValid{}
	if op.Name() != "pathLenValid" {
		t.Errorf("expected pathLenValid, got %s", op.Name())
	}
}

func TestPathLenValidNilContext(t *testing.T) {
	op := PathLenValid{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestPathLenValidNilCert(t *testing.T) {
	op := PathLenValid{}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Type: "root",
			Cert: nil,
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil cert should return false")
	}
}

func TestValidityPeriodDaysName(t *testing.T) {
	op := ValidityPeriodDays{}
	if op.Name() != "validityDays" {
		t.Errorf("expected validityDays, got %s", op.Name())
	}
}

func TestValidityPeriodDaysNilContext(t *testing.T) {
	op := ValidityPeriodDays{}
	got, err := op.Evaluate(nil, nil, []any{1, 365})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestSANRequiredIfEmptySubjectName(t *testing.T) {
	op := SANRequiredIfEmptySubject{}
	if op.Name() != "sanRequiredIfEmptySubject" {
		t.Errorf("expected sanRequiredIfEmptySubject, got %s", op.Name())
	}
}

func TestSANRequiredIfEmptySubjectNilContext(t *testing.T) {
	op := SANRequiredIfEmptySubject{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestKeyUsageCAName(t *testing.T) {
	op := KeyUsageCA{}
	if op.Name() != "keyUsageCA" {
		t.Errorf("expected keyUsageCA, got %s", op.Name())
	}
}

func TestKeyUsageCANilContext(t *testing.T) {
	op := KeyUsageCA{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestKeyUsageLeafName(t *testing.T) {
	op := KeyUsageLeaf{}
	if op.Name() != "keyUsageLeaf" {
		t.Errorf("expected keyUsageLeaf, got %s", op.Name())
	}
}

func TestKeyUsageLeafNilContext(t *testing.T) {
	op := KeyUsageLeaf{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestNoUniqueIdentifiersName(t *testing.T) {
	op := NoUniqueIdentifiers{}
	if op.Name() != "noUniqueIdentifiers" {
		t.Errorf("expected noUniqueIdentifiers, got %s", op.Name())
	}
}

func TestNoUniqueIdentifiersNilContext(t *testing.T) {
	op := NoUniqueIdentifiers{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestSerialNumberUniqueName(t *testing.T) {
	op := SerialNumberUnique{}
	if op.Name() != "serialNumberUnique" {
		t.Errorf("expected serialNumberUnique, got %s", op.Name())
	}
}

func TestSerialNumberUniqueNilContext(t *testing.T) {
	op := SerialNumberUnique{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}
