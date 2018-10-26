package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/auth0-community/go-auth0"
	"github.com/stretchr/testify/assert"
	"github.com/thisendout/apollo"
)

type Auth0TestTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	GrantType    string `json:"grant_type"`
}

func getEnvOrPanic(key string) string {
	e := os.Getenv(key)
	if e == "" {
		panic(fmt.Sprintf("testing: env var %v is empty. If you want to skip the Auth0 integration tests, add the --short flag.", key))
	}
	return e
}

//NOTE: to get the settings below, to to the 'test' tab of the API settings on the Auth0 dashboard.
func getTestBearerToken() string {
	url := getEnvOrPanic("AUTH0_TESTING_URL")

	tokenReq := Auth0TestTokenRequest{
		ClientID:     getEnvOrPanic("AUTH0_CLIENT_ID"),
		ClientSecret: getEnvOrPanic("AUTH0_CLIENT_SECRET"),
		Audience:     getEnvOrPanic(Auth0AudienceEnvKey),
		GrantType:    "client_credentials",
	}

	tokenReqSerial, err := json.Marshal(tokenReq)
	if err != nil {
		panic(err)
	}
	payload := bytes.NewReader(tokenReqSerial)

	req, _ := http.NewRequest("POST", url, payload)

	req.Header.Add("content-type", "application/json")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	var response map[string]interface{}
	json.Unmarshal(body, &response)

	t := response["access_token"]

	token, success := t.(string)
	if !success {
		panic("type assertion of token failed")
	}

	return token

}

func getLiveAuth0Validator() *auth0.JWTValidator {
	// get the Auth0 constants
	jwkURI := getEnvOrPanic(JWKURIEnvKey)
	auth0Domain := getEnvOrPanic(Auth0DomainEnvKey)
	auth0Audience := getEnvOrPanic(Auth0AudienceEnvKey)

	// initiate the Auth0 JWT validator object
	return NewAuth0Validator(auth0Domain, jwkURI, []string{auth0Audience})
}

func Test_Auth0_Reject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Auth0 integration test in short mode.")
	}
	var hostURL string
	arrived := false

	// initiate a test microservice to forward requests to
	targetService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		arrived = true
		hostURL = r.URL.Path
		return
	}))
	defer targetService.Close()

	// init the background context
	ctx := context.Background()

	// build the root middleware chain
	chain := apollo.New().With(ctx)

	// test API config declaration
	testEndpointPrefix := "/test"
	config := APIDeclaration{
		TargetURL:   targetService.URL,
		Prefix:      testEndpointPrefix,
		StripPrefix: false,
		Auth:        true,
		Name:        "test",
	}

	// initiate the LIVE Auth0 JWT validator object (calls the Auth0 test API)
	validator := getLiveAuth0Validator()

	// start the test gateway
	mux := buildServeMux(chain, GatewaySettings{
		APIConfigs:           []APIDeclaration{config},
		requestAuthenticator: validator,
	})
	testGateway := httptest.NewServer(mux)
	defer testGateway.Close()

	// send a test request
	resp, err := http.Get(testGateway.URL + testEndpointPrefix)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "got unexpected status code from target service")
	assert.False(t, arrived, "request arrived at target service, but should have been stopped by Auth middleware")
	assert.Equal(t, "", hostURL)

}

// basically a copy of the above test, but covers a very stupid regression scenario where the wrong handler was added.
func Test_Auth0_Reject_AndStripPrefix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Auth0 integration test in short mode.")
	}
	var hostURL string
	arrived := false

	// initiate a test microservice to forward requests to
	targetService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		arrived = true
		hostURL = r.URL.Path
		return
	}))
	defer targetService.Close()

	// init the background context
	ctx := context.Background()

	// build the root middleware chain
	chain := apollo.New().With(ctx)

	// test API config declaration
	testEndpointPrefix := "/test"
	config := APIDeclaration{
		TargetURL:   targetService.URL,
		Prefix:      testEndpointPrefix,
		StripPrefix: true,
		Auth:        true,
		Name:        "test",
	}

	// initiate the LIVE Auth0 JWT validator object (calls the Auth0 test API)
	validator := getLiveAuth0Validator()

	// start the test gateway
	mux := buildServeMux(chain, GatewaySettings{
		APIConfigs:           []APIDeclaration{config},
		requestAuthenticator: validator,
	})
	testGateway := httptest.NewServer(mux)
	defer testGateway.Close()

	// send a test request
	resp, err := http.Get(testGateway.URL + testEndpointPrefix)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "got unexpected status code from target service")
	assert.False(t, arrived, "request arrived at target service, but should have been stopped by Auth middleware")
	assert.Equal(t, "", hostURL)

}

func Test_Auth0_Accept(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Auth0 integration test in short mode.")
	}
	var hostURL string
	arrived := false

	// initiate a test microservice to forward requests to
	targetService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		arrived = true
		hostURL = r.URL.Path
		return
	}))
	defer targetService.Close()

	// init the background context
	ctx := context.Background()

	// build the root middleware chain
	chain := apollo.New().With(ctx)

	// test API config declaration
	testEndpointPrefix := "/test"
	config := APIDeclaration{
		TargetURL:   targetService.URL,
		Prefix:      testEndpointPrefix,
		StripPrefix: false,
		Auth:        true,
		Name:        "test",
	}

	// initiate the Auth0 JWT validator object
	validator := getLiveAuth0Validator()

	// start the test gateway
	mux := buildServeMux(chain, GatewaySettings{
		APIConfigs:           []APIDeclaration{config},
		requestAuthenticator: validator,
	})
	testGateway := httptest.NewServer(mux)
	defer testGateway.Close()

	// get an Auth0 impersonation token
	token := getTestBearerToken()

	// build the test request with the token using the Bearer scheme
	url := testGateway.URL + testEndpointPrefix
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("authorization", "Bearer "+token)

	//send the request
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)

	// Check whether the request has properly arrived
	assert.Equal(t, http.StatusOK, resp.StatusCode, "got unexpected status code from target service")
	assert.True(t, arrived, "request did not arrive at target service")
	assert.Equal(t, testEndpointPrefix, hostURL)

}
