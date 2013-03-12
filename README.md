gserviceauth
============

This is here for posterity purposes now that jwt is actually in goauth2

INSTEAD USE:

```go
import "code.google.com/p/goauth2/oauth/jwt"

func fetchToken() (string, error) {
	// Read the pem file bytes for the private key.
	keyBytes, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		return "", err
	}

	t := jwt.NewToken(*serviceEmail, *scopes, keyBytes)
	c := &http.Client{}

	// Get the access token.
	o, err := t.Assert(c)
	if err != nil {
		return "", err
	}
	return o.AccessToken, nil
}
```

This was a library for jwt flow auth before one was added oauth2
