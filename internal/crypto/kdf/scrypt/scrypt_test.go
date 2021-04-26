package scrypt

import (
	"log"
	"testing"
	"time"

	"github.com/restic/restic/internal/crypto/kdf"
)

func TestArbitarycalibrate(t *testing.T) {
	var tKDFEngine kdf.KDFEngine = ScryptKDF{}

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

var TEST_PARAMS_VALID = kdf.KDFParams{
	SCRYPT_PARAM_N: 16384,
	SCRYPT_PARAM_R: 8,
	SCRYPT_PARAM_P: 1,
}

var TEST_PARAMS_INVALID_A = kdf.KDFParams{
	SCRYPT_PARAM_N: 69420,
	SCRYPT_PARAM_P: 1,
	SCRYPT_PARAM_R: 8,
}

var TEST_PARAMS_INVALID_B = kdf.KDFParams{
	SCRYPT_PARAM_N: 8,
}

func TestValidate(t *testing.T) {
	var tKDFEngine kdf.KDFEngine = ScryptKDF{}

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
	if result {
		t.Fatal("invalid parameters should cause validate to return 0")
	}
	// This should fail
	result, err = tKDFEngine.Validate(TEST_PARAMS_INVALID_B)
	if err == nil {
		t.Fatal("Invalid parameters should have failed.")
	}
	if result {
		t.Fatal("invalid parameters should cause validate to return 0")
	}

}

func TestConstuct(t *testing.T) {

	{
		_, err := (ScryptKDF{}).Construct(TEST_PARAMS_VALID)
		if err != nil {
			t.Fatalf("valid parameters should not cause an error: %v", err)
		}
	}
	{
		_, err := (ScryptKDF{}).Construct(TEST_PARAMS_INVALID_A)
		if err == nil {
			t.Fatalf("invalid parameters should cause Construct() to fail")
		}
	}
	{
		_, err := (ScryptKDF{}).Construct(TEST_PARAMS_INVALID_B)
		if err == nil {
			t.Fatalf("invalid parameters should cause Construct() to fail")
		}
	}
}
