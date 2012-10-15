// Copyright 2012 All Rights Reserved.
// Author: dougfritz@gmail.com (Doug Fritz)

/*
  For now it can't read p12 files so strip them to just the rsa key with openssl
	openssl pkcs12 -in file.p12 -nocerts -out key.pem -nodes
	then delete the extra text
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
	"sync"
	"time"
)

const (
	aud       = "https://accounts.google.com/o/oauth2/token"
	grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

var (
	separator = []byte{'.'}
)

type gserviceauth struct {
	Email string
	Scope []string
	Key   *rsa.PrivateKey
	token string
	stop  chan bool
	m     *sync.Mutex
}

func ReadKey(keyFile string) (*rsa.PrivateKey, error) {
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

func New(email string, scope []string, key *rsa.PrivateKey) (*gserviceauth, error) {
	auth := new(gserviceauth)
	auth.Email = email
	auth.Scope = scope
	auth.Key = key
  token, err := auth.fetchToken()
  if err != nil {
    return nil, err
  }
  auth.token = token
  auth.stop = make(chan bool)
  auth.m = new(sync.Mutex)
	go auth.autoRefresh()
	return auth, nil
}

func (auth *gserviceauth) assertion() ([]byte, error) {
	header, err := json.Marshal(
		map[string]interface{}{
			"typ": "JWT",
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
	signature, err := rsa.SignPKCS1v15(rand.Reader, auth.Key, crypto.SHA256, sha.Sum(nil))
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

func (auth *gserviceauth) fetchToken() (string, error) {
	assertion, err := auth.assertion()
	if err != nil {
		return "", err
	}
	values := url.Values{"grant_type": {grantType}, "assertion": {string(assertion)}}
	resp, err := http.PostForm(aud, values)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var data authResp
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "", err
	}
	if len(data.Error) != 0 {
		return "", errors.New(data.Error)
	}
	return data.AccessToken, nil
}

func (auth *gserviceauth) autoRefresh() {
  for {
    select {
    case <-time.After(time.Minute * 55):
      token, err := auth.fetchToken()
      if err != nil {
        panic(err)
      }
      auth.m.Lock()
      auth.token = token
      auth.m.Unlock()
      break
    case <-auth.stop:
      return
    }
  }
}

// Sends the stop command to no longer autoRefresh the token
func (auth *gserviceauth) Stop() {
  auth.stop <- true
}

// Gets the current token for use, this will autoRefresh so it is valid
func (auth *gserviceauth) Token() string {
  auth.m.Lock()
  token := auth.token
  auth.m.Unlock()
  return token
}

