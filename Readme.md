# Password

Password is a go library for simple password management with best available option and be able to change it in the future when the best available option changes.

Right now the best available option is [argon2id](https://github.com/P-H-C/phc-winner-argon2
) and recommended defaults

Also some validations are performed by default. Password contain not less than 4 unique and 8 total characters, should contain at least one `number` and one `UpperCase` letter. It's possible to user custom validator by using `WithValidator`
## Usage

```go
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
```

Also there is a `Session` function that generates base64 encoded 16 bytes length string that can be used as a session key

```go
sess, err := password.Session()
if err != nil {
  panic(err)
}
fmt.Println(sess)
```


And there is a way to customize default validator

```go
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
```
