package kdf

import (
	"encoding/json"
	"fmt"
	"time"
)

// Default amount of time to calibrate values for KDF for.
const DefaultCalibrationTimeout time.Duration = 5 * time.Second

// KDFParams are a mapping of string to interface, which will be JSON marshalled.
type KDFParams map[string]interface{}

func (p KDFParams) String() string {
	sjson, err := json.Marshal(p)
	if err != nil {
		return fmt.Sprintf("<KDFParams with bad state? %v>", err)
	}
	return fmt.Sprintf("<KDFParams json=%v >", string(sjson))
}

var KDFImplementations map[string]KDFImpl

// A KDF Engine should derive a value from a password, salt, and length of key
// as well as create optimal parameters for the given amount of time.

//KDFImpl represents the most basic interface for a KDF.
type KDFImpl interface {
	// construct takes a set of parameters and create a KDFEngine.
	Construct(KDFParams) (KDFImpl, error)
	// Derive a key from the given parameters, password, salt, and length
	Derive(string, []byte, int) ([]byte, error)
	// Calibrate creates a set of KDF parameters that cause a single
	// round to take as close to but no more than the given time
	Calibrate(time.Duration) (KDFParams, error)
	// Validate a set of parameters, returning `nil` if ok, error otherwise.
	Validate(KDFParams) (bool, error)
}
