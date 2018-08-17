package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/thisendout/apollo"
	"gopkg.in/square/go-jose.v2/jwt"
)

type dummyJWTValidator struct{}

func (d dummyJWTValidator) ValidateRequest(r *http.Request) (*jwt.JSONWebToken, error) {
	return nil, errors.New("dummy JWT validator always rejects the JWT")
}

// TODO: this is just a smoke test
func TestGetAndValidateConfig(t *testing.T) {
	testConfigFile := `
	[
  {
    "TargetURL" : "http://searchservice:8080",
    "Prefix": "/search",
    "StripPrefix": true,
    "Name" : "search service",
    "Auth" : true,
    "RateLimitPerSecond": 4,
    "CORS" : {
      "AllowedOrigins" : ["*.$REDACTED.nl"],
      "AllowCredentials" : true,
      "AllowedHeaders": ["Authorization", "Content-Type"]
    }
  }
]
`
	testFileName := "./testConfig.json"
	ioutil.WriteFile(testFileName, []byte(testConfigFile), 0644)
	defer os.Remove(testFileName)
	GetAndValidateConfig(testFileName)

}

func Test_Gateway(t *testing.T) {
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
	chain := apollo.New(apollo.Wrap(myRecoveryHandler)).With(ctx)

	// test API config declaration
	testEndpointPrefix := "/test"
	config := APIDeclaration{
		TargetURL:   targetService.URL,
		Prefix:      testEndpointPrefix,
		StripPrefix: false,
		Auth:        false,
		Name:        "test",
	}

	// start the test gateway
	mux := buildServeMux(chain, []APIDeclaration{config}, dummyJWTValidator{})
	testGateway := httptest.NewServer(mux)
	defer testGateway.Close()

	// send a test request
	resp, err := http.Get(testGateway.URL + testEndpointPrefix)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "got unexpected status code from target service")
	assert.True(t, arrived, "request did not arrive at target service")
	assert.Equal(t, testEndpointPrefix, hostURL, "URL path at which target service was hit was unexpected")

}

func Test_Gateway_StripPrefix(t *testing.T) {
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
	chain := apollo.New(apollo.Wrap(myRecoveryHandler)).With(ctx)

	// test API config declaration
	testEndpointPrefix := "/test"
	config := APIDeclaration{
		TargetURL:   targetService.URL,
		Prefix:      testEndpointPrefix,
		StripPrefix: true,
		Auth:        false,
		Name:        "test",
	}

	// start the test gateway
	mux := buildServeMux(chain, []APIDeclaration{config}, dummyJWTValidator{})
	testGateway := httptest.NewServer(mux)
	defer testGateway.Close()

	// send a test request
	resp, err := http.Get(testGateway.URL + testEndpointPrefix)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "got unexpected status code from target service")
	assert.True(t, arrived, "request did not arrive at target service")
	assert.Equal(t, "/", hostURL, "prefix appears not to have been stripped")

}

func Test_Gateway_Ratelimit(t *testing.T) {
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
	chain := apollo.New(apollo.Wrap(myRecoveryHandler)).With(ctx)

	// test API config declaration
	testEndpointPrefix := "/test"
	config := APIDeclaration{
		TargetURL:          targetService.URL,
		Prefix:             testEndpointPrefix,
		RateLimitPerSecond: 1,
		StripPrefix:        true,
		Auth:               false,
		Name:               "test",
	}

	// start the test gateway
	mux := buildServeMux(chain, []APIDeclaration{config}, dummyJWTValidator{})
	testGateway := httptest.NewServer(mux)
	defer testGateway.Close()

	// send 2 rapidly subsequent test requests
	resp1, err := http.Get(testGateway.URL + testEndpointPrefix)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp1.StatusCode, "got unexpected status code from target service")
	assert.True(t, arrived, "request did not arrive at target service")
	assert.Equal(t, "/", hostURL, "prefix appears not to have been stripped")

	// reset the mock server
	arrived = false
	hostURL = ""

	resp2, err := http.Get(testGateway.URL + testEndpointPrefix)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp2.StatusCode, "got unexpected status code from target service")
	assert.False(t, arrived, "rate limited request arrived at target service")
	assert.Equal(t, "", hostURL, "prefix appears not to have been stripped")

}

func Test_Gateway_Auth_Reject(t *testing.T) {
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
	validator := NewAuth0Validator()

	// start the test gateway
	mux := buildServeMux(chain, []APIDeclaration{config}, validator)
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
func Test_Gateway_Auth_Reject_AndStripPrefix(t *testing.T) {
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
	validator := NewAuth0Validator()

	// start the test gateway
	mux := buildServeMux(chain, []APIDeclaration{config}, validator)
	testGateway := httptest.NewServer(mux)
	defer testGateway.Close()

	// send a test request
	resp, err := http.Get(testGateway.URL + testEndpointPrefix)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "got unexpected status code from target service")
	assert.False(t, arrived, "request arrived at target service, but should have been stopped by Auth middleware")
	assert.Equal(t, "", hostURL)

}

func Test_Gateway_Auth_Accept(t *testing.T) {
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
	validator := NewAuth0Validator()

	// start the test gateway
	mux := buildServeMux(chain, []APIDeclaration{config}, validator)
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

func Test_Gateway_GzipOn(t *testing.T) {
	var hostURL string
	arrived := false

	// initiate a test microservice to forward requests to
	targetService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// send a fat random payload
		token := make([]byte, 100000)
		rand.Read(token)
		w.Write(token)

		arrived = true
		hostURL = r.URL.Path
		return
	}))
	defer targetService.Close()

	// init the background context
	ctx := context.Background()

	// build the root middleware chain
	chain := apollo.New().With(ctx)

	originsThatWeAllow := []string{"http://staging.$REDACTED.nl"}

	// test API config declaration
	testEndpointPrefix := "/test"
	config := APIDeclaration{
		TargetURL:   targetService.URL,
		Prefix:      testEndpointPrefix,
		StripPrefix: false,
		Auth:        true,
		Gzip:        true,
		Name:        "test",
		CORS: &CorsOptions{
			AllowCredentials: true,
			AllowedOrigins:   originsThatWeAllow,
		},
	}

	// initiate the Auth0 JWT validator object
	validator := NewAuth0Validator()

	// start the test gateway
	mux := buildServeMux(chain, []APIDeclaration{config}, validator)
	testGateway := httptest.NewServer(mux)
	defer testGateway.Close()

	// get an Auth0 impersonation token
	token := getTestBearerToken()

	// build the test request with the token using the Bearer scheme
	url := testGateway.URL + testEndpointPrefix
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Add("authorization", "Bearer "+token)
	req.Header.Add("Accept-Encoding", "gzip")
	req.Header.Add("Origin", originsThatWeAllow[0])
	req.Header.Add("Access-Control-Request-Method", "POST")

	//send the request
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)

	// Check whether the request has properly arrived
	assert.Equal(t, http.StatusOK, resp.StatusCode, "got unexpected status code from target service")
	assert.True(t, arrived, "request did not arrive at target service")
	assert.Equal(t, testEndpointPrefix, hostURL)

	// check if the gzip content header is set
	assert.True(t, resp.Header.Get("Content-Encoding") == "gzip", "gzip content-encoding header not set: ", resp.Header)

}

// Check if a CORS preflight request returns the proper headers
func TestGateway_CORS_preflight(t *testing.T) {
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

	originsThatWeAllow := []string{"http://staging.$REDACTED.nl"}

	// test API config declaration
	testEndpointPrefix := "/test"
	config := APIDeclaration{
		TargetURL:   targetService.URL,
		Prefix:      testEndpointPrefix,
		StripPrefix: true,
		Auth:        true,
		Name:        "test",
		CORS: &CorsOptions{
			//AllowCredentials: true,
			AllowedOrigins: originsThatWeAllow,
		},
	}

	// initiate the Auth0 JWT validator object
	validator := NewAuth0Validator()

	// start the test gateway
	mux := buildServeMux(chain, []APIDeclaration{config}, validator)
	testGateway := httptest.NewServer(mux)
	defer testGateway.Close()

	// get an Auth0 impersonation token
	token := getTestBearerToken()

	// build the test request with the token using the Bearer scheme
	url := testGateway.URL + testEndpointPrefix
	req, _ := http.NewRequest("OPTIONS", url, nil)

	// add a mock origin header that should be rejected
	req.Header.Add("Origin", "http://foo.com")
	req.Header.Add("Access-Control-Request-Method", "POST")
	req.Header.Add("authorization", "Bearer "+token)

	//send the request
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)

	// preflight should be aborted as the origin is not allowed
	assert.Equal(t, http.StatusOK, resp.StatusCode, "got unexpected status code from target service")
	assert.False(t, arrived, "preflight request arrived to top handler while preflight should have been aborted")
	assert.Equal(t, "", hostURL)
}

//NOTE: to get the settings below, to to the 'test' tab of the API settings on the Auth0 dashboard.
func getTestBearerToken() string {
	url := "https://$REDACTED.eu.auth0.com/oauth/token"

	payload := strings.NewReader("{\"client_id\":\"$REDACHTED\",\"client_secret\":\"$REDACTED\",\"audience\":\"api.$REDACTED.nl\",\"grant_type\":\"client_credentials\"}")

	req, _ := http.NewRequest("POST", url, payload)

	req.Header.Add("content-type", "application/json")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	var response map[string]interface{}
	json.Unmarshal(body, &response)

	t := response["access_token"]

	token, err := t.(string)
	if !err {
		panic("type assertion of token failed")
	}

	return token

}
