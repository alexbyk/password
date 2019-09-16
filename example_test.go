package password_test

import (
	"fmt"

	"github.com/alexbyk/password"
)

func ExampleVerify() {

	// generate a hash and store it somewhere
	hashed, err := password.Hash("VeryS3cred")
	if err != nil {
		panic(err)
	}

	// than fetch a hashed password and compare with provided by a user
	if err := password.Verify(hashed, "VeryS3cred"); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Ok")
	}

	if err := password.Verify(hashed, "Wrong"); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Ok")
	}

	// Output:
	// Ok
	// Invalid password
}

func ExampleSession() {
	sess, err := password.Session()
	if err != nil {
		panic(err)
	}
	fmt.Println(sess)
}

func ExampleWithValidator() {
	pass := password.WithValidator(func(str string) error {
		if len(str) < 8 {
			return fmt.Errorf("Too short")
		}
		return nil
	})

	_, err := pass.Hash("aaa")
	fmt.Println(err)

	hash, _ := pass.Hash("very4568")
	if pass.Verify(hash, "very4568") == nil {
		fmt.Println("Ok")
	}

	// Output:
	// Too short
	// Ok
}
