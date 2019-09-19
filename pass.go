/*Package password provides easy to user function for password management wich are
secure by default. It users argon2id algorithm and handles salt generation*/
package password

import (
	"fmt"
	"unicode"
)

// Password is a handler for password manager with validator
type Password struct {
	validator func(pass string) error
}

func checkMalformed(plain string) error {
	if plain == "" {
		return ErrEmptyPassword
	}
	for _, ch := range plain {
		if unicode.IsSpace(ch) {
			return ErrMalformedPassword
		}
	}
	return nil
}

// Hash returns a hash of the password
func (p *Password) Hash(plain string) (string, error) {
	// Just to show that the logic in caller is wrong
	if err := checkMalformed(plain); err != nil {
		return "", err
	}

	if p.validator != nil {
		if err := p.validator(plain); err != nil {
			return "", err
		}
	}
	hashed, err := hashArgon2id(plain)
	return hashed, err
}

// ErrMalformedPassword If password contains space
var ErrMalformedPassword = fmt.Errorf("Password shouldn't contain spaces")

// ErrWeekPassword is returned by Hash function when the password is too week
var ErrWeekPassword = fmt.Errorf("Password is too weak. Should contain minimum 8 characters (4 unique at least), numbers and UpperCase letters")

// Verify returns an error if password don't match
func (p *Password) Verify(hashed, password string) error {
	return verifyArgon2id(hashed, password)
}

/*IsStrong checks if the password is strong enough */
func IsStrong(plain string) error {
	chars := map[rune]bool{}
	var upper, number bool
	for _, r := range plain {
		chars[r] = true
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsNumber(r):
			number = true
		}
	}

	if !(len(plain) > 7 && len(chars) > 4 && upper && number) {
		return ErrWeekPassword
	}

	return nil
}

var strongPass = &Password{validator: IsStrong}
var anyPass = &Password{}

/*Hash returns a hash that can be used for Verify.
Salt is generated automatically, the returning result will be in crypt(3) format
Hashing alrorythm is argon2id right now.

To implement other checker, use WithChecker()

Also password shouln't contain unicode space character and shoudn't be empty

The password should pass default checker:
>= 8 characters && >= 4 total characters and contain number and uppercase letter. To avoid weakness validation, use HashNoValidation
*/
func Hash(plainPassword string) (string, error) { return strongPass.Hash(plainPassword) }

/*HashSkipValidation does generates a hash but skips weakness validation. But still, password shouldn't contain spaces and be empty
*/
func HashSkipValidation(plainPassword string) (string, error) { return anyPass.Hash(plainPassword) }

// Verify compairs result of Hash with a password and returns nil if hash was generated from provided password
func Verify(hashed, plain string) error { return strongPass.Verify(hashed, plain) }

// WithValidator returns a password object with custom checker
func WithValidator(fn func(string) error) *Password {
	return &Password{fn}
}
