gserviceauth
============

This is here for posterity purposes now that jwt is actually in goauth2

INSTEAD USE:

https://code.google.com/p/goauth2/

`go get code.google.com/p/goauth2/oauth`

Get your service email and your p12 private key from the Google API Console.
For now it can't read p12 files so strip them to just the rsa key with
openssl `openssl pkcs12 -in file.p12 -nocerts -out key.pem -nodes` then delete the extra text

Then:

```go
package main

import (
  "code.google.com/p/goauth2/oauth/jwt"
  "flag"
  "fmt"
  "http"
  "io/ioutil"
)

var (
  serviceEmail = flag.String("service_email", "", "OAuth service email.")
  keyPath      = flag.String("key_path", "key.pem", "Path to unencrypted RSA private key file.")
  scope        = flag.String("scope", "", "Space separated scopes.")
)

func fetchToken() (string, error) {
    // Read the pem file bytes for the private key.
    keyBytes, err := ioutil.ReadFile(*keyPath)
    if err != nil {
        return "", err
    }

    t := jwt.NewToken(*serviceEmail, *scope, keyBytes)
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
