package main

import (
	"net/http"

	"github.com/auth0-community/go-auth0"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type JWTRequestValidator interface {
	ValidateRequest(r *http.Request) (*jwt.JSONWebToken, error)
}

func NewAuth0Validator(domain, jwkURI string, audiences []string) *auth0.JWTValidator {
	client := auth0.NewJWKClient(auth0.JWKClientOptions{URI: jwkURI}, nil) // nil -> default token extractor (fromheader)
	configuration := auth0.NewConfiguration(client, audiences, domain, jose.RS256)
	validator := auth0.NewValidator(configuration, nil) // nil -> default token extractor (fromheader)
	return validator
}
