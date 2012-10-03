// Copyright 2012 All Rights Reserved.
// Author: dougfritz@gmail.com (Doug Fritz)

/*
  For now it can't read p12 files so strip them to just the rsa key with openssl
	openssl pkcs12 -in file.p12 -nocerts -out key.pem -nodes
*/

package gserviceauth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
	"fmt"
)

const (
	aud       = "https://accounts.google.com/o/oauth2/token"
	grantType = "urn:ietf:params:oauth:grant-type:gserviceauth-bearer"
)

var (
	separator = []byte{'.'}
)

type gserviceauth struct {
	Email string
	Scope []string
	key   *rsa.PrivateKey
	token []byte
}

func readKey(keyFile string) (*rsa.PrivateKey, error) {
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil {
		return nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func b64urlencode(b []byte) []byte {
	encoded := []byte(base64.URLEncoding.EncodeToString(b))
	var equalIndex = bytes.Index(encoded, []byte{'='})
	if equalIndex > -1 {
		encoded = encoded[:equalIndex]
	}
	return encoded
}

func New(email string, scope []string, keyPath string) (*gserviceauth, error) {
	auth := new(gserviceauth)
	auth.Email = email
	auth.Scope = scope
	k, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	auth.key = k
	return auth, nil
}

func (auth *gserviceauth) assertion() ([]byte, error) {
	header, err := json.Marshal(
		map[string]interface{}{
			"typ": "gserviceauth",
			"alg": "RS256",
		})
	if err != nil {
		return nil, err
	}
	parts := [3][]byte{}
	parts[0] = b64urlencode(header)
	now := time.Now()
	claims, err := json.Marshal(
		map[string]interface{}{
			"iss":   auth.Email,
			"scope": strings.Join(auth.Scope, " "),
			"aud":   aud,
			"exp":   now.Add(time.Hour).Unix(),
			"iat":   now.Unix(),
		})
	if err != nil {
		return nil, err
	}
	parts[1] = b64urlencode(claims)

	sha := sha256.New()
	sha.Write(bytes.Join(parts[:2], separator))
	signature, err := rsa.SignPKCS1v15(rand.Reader, auth.key, crypto.SHA256, sha.Sum(nil))
	if err != nil {
		return nil, err
	}
	parts[2] = b64urlencode(signature)
	return bytes.Join(parts[:], separator), nil
}

type authResp struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (auth *gserviceauth) Token() ([]byte, error) {
	assertion, err := auth.assertion()
	if err != nil {
		return nil, err
	}
	values := url.Values{"grant_type": {grantType}, "assertion": {string(assertion)}}
	fmt.Println(values.Encode())
	resp, err := http.PostForm(aud, values)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// var data map[string]interface{}
	var data authResp
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}
	if len(data.Error) != 0 {
		return nil, errors.New(data.Error)
	}
	return []byte(data.AccessToken), nil
}
