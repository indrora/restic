package crypto

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	SCRYPT_PARAM_N = "N"
	SCRYPT_PARAM_R = "R"
	SCRYPT_PARAM_P = "P"

	VALUE_R = 8 // Fixed at 8 because reasons
	VALUE_P = 1 // Fixed at 1 because reasons

)

type ScryptKDF struct{}

func (ScryptKDF) Validate(params KDFParams) (bool, error) {
	// We need to check that three different values are there

	if len(params) != 3 {
		return false, fmt.Errorf("incorrect number of parameters. Expected 3, got %v", len(params))
	}

	valN, containsN := params[SCRYPT_PARAM_N]
	valR, containsR := params[SCRYPT_PARAM_R]
	valP, containsP := params[SCRYPT_PARAM_P]

	if !containsN {
		return false, errors.New("missing parameter N")
	}

	if !containsR {
		return false, errors.New("missing parameter R")
	}
	if !containsP {
		return false, errors.New("missing parameter P")
	}

	nValue, nIsInt := valN.(int)
	rValue, rIsInt := valR.(int)
	pValue, pIsInt := valP.(int)

	if !nIsInt {
		return false, errors.New("type of N is not int")
	}
	if !rIsInt {
		return false, errors.New("type of R is not int")
	}
	if !pIsInt {
		return false, errors.New("type of P is not int")
	}

	// Verify that all parameters are > 0
	if nValue < 1 {
		return false, errors.New("value of N < 1")
	}
	if (nValue & (nValue - 1)) == 0 {
		return false, errors.New("n must be power of 2")
	}

	if rValue < 1 {
		return false, errors.New("value of R < 1")
	}
	if pValue < 1 {
		return false, errors.New("value of P < 1")
	}

	return true, nil

}

func (ScryptKDF) Derive(params KDFParams, password string, salt []byte, len int) ([]byte, error) {

	// Walk through the crypto...

	n := params[SCRYPT_PARAM_N].(int)
	r := params[SCRYPT_PARAM_R].(int)
	p := params[SCRYPT_PARAM_P].(int)

	key, err := scrypt.Key([]byte(password), salt, n, r, p, len)

	if err != nil {
		return nil, err
	}

	return key, nil

}

func (ScryptKDF) Calibrate(limit time.Duration) (KDFParams, error) {
	if limit == 0 {
		limit = defaultTimeout
	}
	// We're going to go with the suggestions from Filippo:
	// https://blog.filippo.io/the-scrypt-parameters/

	// Fillipo's basic argument is thus: N is the only work factor, and should be a power of 2.
	// In the actual scrypt paper itself, there are a handful of implementations that are suggested,
	// but the starting point of 2^10 is a good place to start for modern systems. Why stop there, though?
	// We want the highest work factor that we can get that doesn't exceed the duration, so we're going to
	// take powers of 2 and raise those to powers of two, then back that value off until it's under our
	// limit.

	// We need some data for scrypt to work with. We're going to generate some garbage

	salt := make([]byte, 32)
	pass := make([]byte, 64)

	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(pass)
	if err != nil {
		return nil, err
	}

	// This starts with the recommended 16384 value.
	testNExponent := 16
	elapsed := time.Duration(0)
	for elapsed < limit {
		testNExponent += 2
		elapsed, err = timeScrypt(int(math.Pow(2, float64(testNExponent))), pass, salt)
		if err != nil {
			return nil, err
		}
	}
	// Now, we tune a second time
	elapsed = time.Duration(0)
	for elapsed < limit {
		testNExponent--
		elapsed, err = timeScrypt(int(math.Pow(2, float64(testNExponent))), pass, salt)
		if err != nil {
			return nil, err
		}
	}

	return KDFParams{
		SCRYPT_PARAM_N: int(math.Pow(2, float64(testNExponent))),
		SCRYPT_PARAM_P: VALUE_P,
		SCRYPT_PARAM_R: VALUE_R,
	}, nil
}

func timeScrypt(n int, pass []byte, salt []byte) (time.Duration, error) {
	start := time.Now()
	_, err := scrypt.Key(pass, salt, n, 8, 1, 32)
	if err != nil {
		return -1, err
	}
	end := time.Now()
	return end.Sub(start), nil

}
