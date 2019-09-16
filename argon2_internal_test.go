package password

import (
	"encoding/base64"
	"testing"

	"github.com/alexbyk/ftest"
)

func Test_empty(t *testing.T) {

	ft := ftest.New(t)
	_, err := hashArgon2id("")
	ft.Eq(err, ErrEmptyPassword)

	ft.Eq(err, ErrEmptyPassword)
}

func Test_parseOpts_errors(t *testing.T) {
	ft := ftest.New(t)
	// echo -n "pass" | ./argon2 somesalt -id
	params, err := parseOpts(`$argon2id$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`)
	ft.Nil(err)
	expected := &argonOpts{
		moniker: "argon2id",
		v:       19,
		m:       4096,
		t:       3,
		p:       1,
	}
	expected.hashed, _ = base64.RawStdEncoding.Strict().DecodeString("Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s")
	expected.salt, _ = base64.RawStdEncoding.Strict().DecodeString("c29tZXNhbHQ")
	ft.Eq(params, expected)

	badHashes := []string{
		``,
		// v
		`$argon2id$v=Foo$m=4096,t=3,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$v=18$m=4096,t=3,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$$m=4096,t=3,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$v$m=4096,t=3,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,

		// moniker
		`$Bad$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		// salt
		`$argon2id$v=19$m=4096,t=3,p=1$$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`, // empty salt
		`$argon2id$v=19$m=4096,t=3,p=1$?$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		// pass
		`$argon2id$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$`, // empty
		`$argon2id$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$?`,

		// opts
		`$argon2id$v=19$m=4096,t=3,p=1,$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$v=19t=3,p=$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$v=19$m,t=3,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$v=19$m=,t=3,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$v=19$m=BAD,t=3,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$v=19$Z=4096,t=3,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$v=19$m=4096,t=3,p=0$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
		`$argon2id$v=19$m=4096,t=0,p=1$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,

		`$argon2id$v=19$m=4096,t=3,p=BAD$c29tZXNhbHQ$Owaog30Ihz1ODnekfn3jXvAUq/zVuQ5G5CMM4gzJ+3s`,
	}
	for _, h := range badHashes {
		_, err := parseOpts(h)
		ft.NotNilf(err, h)
	}
}
