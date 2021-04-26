package kdf

import "time"

const DefaultCalibrationTimeout time.Duration = 5 * time.Second

type KDFParams map[string]interface{}

// A KDF Engine should derive a value from a password, salt, and length of key
// as well as create optimal parameters for the given amount of time.

type KDFEngine interface {
	// construct takes a set of parameters and create a KDFEngine.
	Construct(KDFParams) (KDFEngine, error)
	// Derive a key from the given parameters, password, salt, and length
	Derive(string, []byte, int) ([]byte, error)
	// return a set of KDF parameters that cause a single
	// round to take as close to but no more than the given time
	Calibrate(time.Duration) (KDFParams, error)
	// Validate a set of parameters, returning `nil` if ok, error otherwise.
	Validate(KDFParams) (bool, error)
}
