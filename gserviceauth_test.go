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
  key, err := ReadKey(*keyPath)
	if err != nil {
		t.Fatal(err)
	}
	scope := []string{"https://www.googleapis.com/auth/taskqueue"}
	auth, err := New(*serviceEmail, scope, key)
	if err != nil {
	  t.Fatal(err)
  }
  token := auth.Token()
	if token == "" {
		t.Fatal(err)
	}
}

func init() {
	flag.Parse()
}
