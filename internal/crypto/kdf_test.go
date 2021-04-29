package crypto

import (
	"testing"
	"time"

	"github.com/restic/restic/internal/crypto/kdf"
)

func TestCalibrate(t *testing.T) {
	params, err := Calibrate(100*time.Millisecond, 50)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("testing calibrate, params after: %v", params)
}

func TestGetByName(t *testing.T) {
	var impl kdf.KDFImpl

	impl, err := GetKDFByName("scrypt")
	if err != nil {
		t.Fatalf("returned error for known type of kdf implementation: %v", err)
	}
	if impl == nil {
		t.Fatal("returned nil when valid KDF implementation")
	}
}
