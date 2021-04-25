package crypto

import (
	"log"
	"testing"
	"time"
)

func TestCalibrate(t *testing.T) {
	params, err := Calibrate(100*time.Millisecond, 50)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("testing calibrate, params after: %v", params)
}

func TestArbitarycalibrate(t *testing.T) {
	var tKDFEngine KDFEngine = ScryptKDF{}

	params, err := tKDFEngine.Calibrate(5 * time.Second)

	if err != nil || params == nil {
		t.Fatal(err)
	}
	// We guarantee that the value of N will be non-zero and a power of 2
	if params[SCRYPT_PARAM_N].(int) < 1 {
		t.Fatal("Calibrate returned invalid N value")
	}
	nValue := params[SCRYPT_PARAM_N].(int)
	isPowerOfTwo := (nValue & (nValue - 1)) == 0
	if isPowerOfTwo == false {
		log.Fatal("Calibrate returned non-power-of-two.")
	}
	t.Logf("Final N value is %v", nValue)
}

var TEST_PARAMS_VALID = KDFParams{
	SCRYPT_PARAM_N: 16384,
	SCRYPT_PARAM_R: 8,
	SCRYPT_PARAM_P: 1,
}

var TEST_PARAMS_INVALID_A = KDFParams{
	SCRYPT_PARAM_N: 69420,
	SCRYPT_PARAM_P: 1,
	SCRYPT_PARAM_R: 8,
}

var TEST_PARAMS_INVALID_B = KDFParams{
	SCRYPT_PARAM_N: 8,
}

func TestValidate(t *testing.T) {
	var tKDFEngine KDFEngine = ScryptKDF{}

	result, err := tKDFEngine.Validate(TEST_PARAMS_VALID)
	if err != nil {
		t.Fatal(err)
	}
	if result == false {
		t.Fatal("Valid parameters return false in Validate()")
	}
	// This should fail
	result, err = tKDFEngine.Validate(TEST_PARAMS_INVALID_A)
	if err == nil {
		t.Fatal("Invalid parameters should have failed.")
	}
}
