package scrypt

import (
	"log"
	"testing"
	"time"

	"github.com/restic/restic/internal/crypto/kdf"
)

func TestArbitarycalibrate(t *testing.T) {
	var tKDFEngine kdf.KDFImpl = ScryptKDF{}

	params, err := tKDFEngine.Calibrate(1 * time.Second)

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

var TEST_PARAMS_INVALID = []kdf.KDFParams{
	// Values that are out of spec
	{
		SCRYPT_PARAM_N: 69420,
		SCRYPT_PARAM_R: 1,
		SCRYPT_PARAM_P: 1,
	},
	{
		SCRYPT_PARAM_N: 0,
		SCRYPT_PARAM_R: 1,
		SCRYPT_PARAM_P: 1,
	},
	{
		SCRYPT_PARAM_N: 2,
		SCRYPT_PARAM_R: -1,
		SCRYPT_PARAM_P: 1,
	},
	{
		SCRYPT_PARAM_N: 2,
		SCRYPT_PARAM_R: 1,
		SCRYPT_PARAM_P: -1,
	},
	// Values that are the wrong type
	{
		SCRYPT_PARAM_N: "gopher",
		SCRYPT_PARAM_R: 1,
		SCRYPT_PARAM_P: 1,
	},
	{
		SCRYPT_PARAM_N: 2,
		SCRYPT_PARAM_R: "gopher",
		SCRYPT_PARAM_P: 1,
	},
	{
		SCRYPT_PARAM_N: 2,
		SCRYPT_PARAM_R: 1,
		SCRYPT_PARAM_P: "gopher",
	},
	// These should never happen
	{
		SCRYPT_PARAM_N: nil,
		SCRYPT_PARAM_R: 1,
		SCRYPT_PARAM_P: 1,
	},
	{
		SCRYPT_PARAM_N: 2,
		SCRYPT_PARAM_R: nil,
		SCRYPT_PARAM_P: 1,
	},
	{
		SCRYPT_PARAM_N: 2,
		SCRYPT_PARAM_R: 1,
		SCRYPT_PARAM_P: nil,
	},
}

func TestValidate(t *testing.T) {
	var tKDFEngine kdf.KDFImpl = ScryptKDF{}

	result, err := tKDFEngine.Validate(TEST_PARAMS_VALID)
	if err != nil {
		t.Fatal(err)
	}
	if result == false {
		t.Fatal("Valid parameters return false in Validate()")
	}
	for _, testcase := range TEST_PARAMS_INVALID {
		result, err = tKDFEngine.Validate(testcase)
		if result {
			t.Fatalf("invalid parameters allowed as valid: %v", testcase)
		}
		if err == nil {
			t.Fatalf("invalid parameters do not raise error: %v", testcase)
		}
	}

}

func TestConstuct(t *testing.T) {

	{
		_, err := (ScryptKDF{}).Construct(TEST_PARAMS_VALID)
		if err != nil {
			t.Fatalf("valid parameters should not cause an error: %v", err)
		}
	}
	for _, testcase := range TEST_PARAMS_INVALID {
		_, err := (ScryptKDF{}).Construct(testcase)
		if err == nil {
			t.Fatalf("invalid parameters not caught during Construct(): %v", testcase)
		}
	}
}

/*
   scrypt (P="password", S="NaCl",
           N=1024, r=8, p=16, dkLen=64) =
   fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
   7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
   2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
   c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40

*/

func TestKnownVectors(t *testing.T) {
	test_kdf, err := (ScryptKDF{}).Construct(kdf.KDFParams{
		SCRYPT_PARAM_N: 1024,
		SCRYPT_PARAM_R: 8,
		SCRYPT_PARAM_P: 16,
	})
	if err != nil {
		t.Fatalf("failed to init test vectors: %v", err)
	}
	kbytes, err := test_kdf.Derive("password", []byte("NaCl"), 64)
	if err != nil {
		t.Fatalf("failed with known test vectors: %v", err)
	}
	if kbytes[0] != 0xfd {
		t.Fatalf("Error in calculation; expected %v got %v", 0xfd, kbytes[0])
	}

}
