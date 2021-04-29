package crypto

import (
	"fmt"

	"github.com/restic/restic/internal/crypto/kdf"
	kdfscrypt "github.com/restic/restic/internal/crypto/kdf/scrypt"
)

// Return a KDF implementation by name.
func GetKDFByName(name string) (kdf.KDFImpl, error) {
	switch name {
	case "scrypt":
		return kdfscrypt.ScryptKDF{}, nil
	default:
		return nil, fmt.Errorf("unknown KDF type %v", name)
	}
}
