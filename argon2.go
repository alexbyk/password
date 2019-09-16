package password

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// DefaultSaltLength is a lenght of generated salt in bytes
	DefaultSaltLength = 16
	// DefaultTime -> t
	DefaultTime = 1
	// DefaultMemory -> m, in KiB, ~64Mb
	DefaultMemory = 64 * 1024 // KiB
	// DefaultParallelism -> p, number of threads
	DefaultParallelism = 4
	// DefaultLen is the number of resulting bytes
	DefaultLen = 32
)

// ErrBadInput Indicates unsupported hash format
var ErrBadInput = fmt.Errorf("Bad input hash")

// ErrEmptyPassword is an error for bad password (for now it's only empty string case)
var ErrEmptyPassword = fmt.Errorf("Empty password")

// ErrInvalidPassword is a signal that passwords don't match
var ErrInvalidPassword = fmt.Errorf("Invalid password")

func hashArgon2id(password string) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}
	salt, err := Rand(DefaultSaltLength)
	if err != nil {
		return "", err
	}
	hashed := argon2.IDKey([]byte(password), salt, DefaultTime, DefaultMemory, DefaultParallelism, DefaultLen)

	opts := fmt.Sprintf("m=%d,t=%d,p=%d", DefaultMemory, DefaultTime, DefaultParallelism)
	return fmt.Sprintf(`$argon2id$v=%d$%s$%s$%s`, argon2.Version, opts,
		b64.EncodeToString(salt),
		b64.EncodeToString(hashed),
	), nil
}

// verifyArgon2id return true, if password is valid
func verifyArgon2id(hashWithOpts, password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	opts, err := parseOpts(hashWithOpts)
	if err != nil {
		return err
	}
	hashed := argon2.IDKey([]byte(password), opts.salt, opts.t, opts.m, opts.p, uint32(len(opts.hashed)))
	if subtle.ConstantTimeCompare(hashed, opts.hashed) != 1 {
		return ErrInvalidPassword
	}
	return nil
}

type argonOpts struct {
	moniker string
	v       uint8 // version

	// memory, time, parallelizm
	m, t uint32
	p    uint8

	hashed []byte
	salt   []byte
}

func parseOpts(hashed string) (*argonOpts, error) {
	parts := strings.Split(hashed, "$")
	if len(parts) != 6 {
		return nil, ErrBadInput
	}
	ret := argonOpts{}

	// 1 - moniker
	ret.moniker = parts[1]
	if ret.moniker != "argon2id" {
		return nil, ErrBadInput
	}

	// 2 - version
	vArr := strings.Split(parts[2], "=")
	if len(vArr) != 2 {
		return nil, ErrBadInput
	}
	v, err := strconv.ParseUint(vArr[1], 10, 8)
	if err != nil || v != argon2.Version {
		return nil, ErrBadInput
	}
	ret.v = uint8(v)

	// 3 - params
	ret.m, ret.t, ret.p, err = mtp(parts[3])
	if err != nil {
		return nil, ErrBadInput
	}

	// 4 - salt
	ret.salt, err = b64.DecodeString(parts[4])
	if err != nil || len(ret.salt) == 0 {
		return nil, ErrBadInput
	}

	// 5 - pass
	ret.hashed, err = b64.DecodeString(parts[5])
	if err != nil || len(ret.hashed) == 0 {
		return nil, ErrBadInput
	}

	return &ret, nil
}

func mtp(in string) (m, t uint32, p uint8, err error) {
	kvs := strings.Split(in, ",")
	if len(kvs) != 3 {
		err = ErrBadInput
		return
	}
	kvMap := map[string]string{}
	for _, kv := range kvs {
		kvArr := strings.Split(kv, "=")
		if len(kvArr) != 2 {
			err = ErrBadInput
			return
		}
		kvMap[kvArr[0]] = kvArr[1]
	}

	t64, err := strconv.ParseUint(kvMap["m"], 10, 32)
	if err != nil {
		err = ErrBadInput
		return
	}
	m = uint32(t64)

	t64, err = strconv.ParseUint(kvMap["t"], 10, 32)
	if err != nil || t64 < 1 { // IDKey will panic if 0
		err = ErrBadInput
		return
	}
	t = uint32(t64)

	t64, err = strconv.ParseUint(kvMap["p"], 10, 8)
	if err != nil || t64 < 1 { // IDKey will panic if 0
		err = ErrBadInput
		return
	}
	p = uint8(t64)

	return
}
