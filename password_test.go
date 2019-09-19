package password_test

import (
	"fmt"
	"testing"

	"github.com/alexbyk/ftest"
	"github.com/alexbyk/password"
)

func TestHash(t *testing.T) {
	ft := ftest.New(t)
	pass := "v3rYSecret"
	hash, err := password.Hash(pass)

	// echo -n "v3rYSecret" | ./argon2 somesalt -id -t 1 -p 4 -l 32 -k 65536
	ft.Nil(err).Contains(hash, `$argon2id$v=19$m=65536,t=1,p=4`)
	err = password.Verify(hash, pass)
	ft.Nil(err)

	// not the same
	newHash, _ := password.Hash(pass)
	ft.NotEq(newHash, hash)

	// empty password
	hash, err = password.Hash("")
	ft.Eq(err, password.ErrEmptyPassword).Eq(hash, "")

	// badPassword
	hash, _ = password.Hash(pass)
	err = password.Verify(hash, "wrong")
	ft.Eq(err, password.ErrInvalidPassword)
}

func TestCompareVerify_3dimpl(t *testing.T) {
	ft := ftest.New(t)
	pass := "v3rYSecret"
	// echo -n v3rYSecret | ./argon2 somesalt -id -t 1 -p 4 -l 32 -k 65536
	hash := "$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$aiVOfAzd5X5eInc3Uum0mxKT/mprA+unYM5SWn9HTTQ"

	tests := []struct {
		hash, pass string
		valid      bool
	}{
		{hash, pass, true},
		{hash, "pass2", false},
		{hash, "", false},
		{hash + "b", "pass", false},
		{"", "", false},
		{
			`$argon2id$v=19$m=1024,t=1,p=4$c29tZXNhbHQ$aiVOfAzd5X5eInc3Uum0mxKT/mprA+unYM5SWn9HTTQ`, // m
			pass,
			false,
		},
	}

	for _, test := range tests {
		err := password.Verify(test.hash, test.pass)
		ft.Eq(err == nil, test.valid)
	}

}

func TestCompareVerify_errors(t *testing.T) {
	ft := ftest.New(t)
	tests := []struct {
		hash, pass string
	}{
		{
			// t = 0
			`$argon2id$v=19$m=4096,t=0,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
			"pass",
		},
		{
			// p = 0
			`$argon2id$v=19$m=4096,t=3,p=0$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
			"pass",
		},
		{
			// version
			`$argon2id$v=20$m=4096,t=3,p=0$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
			"pass",
		},
		{
			// moniker
			`$argon2i$v=20$m=4096,t=3,p=0$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
			"pass",
		},
		{
			``,
			"pass",
		},
	}

	for _, test := range tests {
		err := password.Verify(test.hash, test.pass)
		ft.NotNil(err)
	}

	ft.Eq(password.Verify("$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$aiVOfAzd5X5eInc3Uum0mxKT/mprA+unYM5SWn9HTTQ", ""), password.ErrEmptyPassword)
}

func TestHash_weekness(t *testing.T) {
	ft := ftest.New(t)
	for _, p := range []string{"a", "aaaaaaaa", "aabbccdd", "aabbccdD"} {
		_, err := password.Hash(p)
		ft.Eqf(err, password.ErrWeekPassword, "%q should be week", p)
	}

	_, err := password.Hash("verYs3cr")
	ft.Nil(err)
}

func TestHash_withoutValidation(t *testing.T) {
	ft := ftest.New(t)
  _, err := password.HashSkipValidation("foo")
  ft.Nil(err)
}


func TestHash_malformed(t *testing.T) {
	ft := ftest.New(t)
	password.Hash("awgh2F9f")

	// empty password
	hash, err := password.Hash("")
	ft.Eq(err, password.ErrEmptyPassword).Eq(hash, "")

	for _, p := range []string{"dfssdgwe39S ", " dfssdgwe39S", "dfssd gwe39S", "abc33\tdesgs"} {
		_, err := password.Hash(p)
		ft.Eqf(err, password.ErrMalformedPassword, "%q should be malformed", p)
	}
}

func Test_WithCheck(t *testing.T) {
	ft := ftest.New(t)
	retErr := fmt.Errorf("Week")
	pass := password.WithValidator(func(str string) error {
		if len(str) < 2 {
			return retErr
		}
		return nil
	})

	_, err := pass.Hash("1")
	ft.Eq(err, retErr)
	_, err = pass.Hash("")
	ft.Eq(err, password.ErrEmptyPassword)

}
