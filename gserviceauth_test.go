// Copyright 2012 All Rights Reserved.
// Author: dougfritz@gmail.com (Doug Fritz)

package gserviceauth

import(
	"testing"
	"flag"
)

var (
	serviceEmail = flag.String("service_email", "test@gserviceaccount.com", "OAuth service email.")
	keyPath = flag.String("key_path", "key.pem", "Path to unencrypted RSA private key file.")
)

func TestGetToken(t *testing.T) {
	scope := []string{"https://www.googleapis.com/auth/taskqueue"}
	auth, err := New(*serviceEmail, scope, *keyPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = auth.Token()
	if err != nil {
		t.Fatal(err)
	}
}

func init() {
	flag.Parse()
}
