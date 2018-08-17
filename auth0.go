package main

import (
	"github.com/auth0-community/auth0"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
)

type RequestJWTValidator interface {
	ValidateRequest(r *http.Request) (*jwt.JSONWebToken, error)
}

func NewAuth0Validator() *auth0.JWTValidator {
	client := auth0.NewJWKClient(auth0.JWKClientOptions{URI: JWKS_URI})

	audience := []string{auth0Audience}

	configuration := auth0.NewConfiguration(client, audience, auth0Domain, jose.RS256)
	validator := auth0.NewValidator(configuration)

	return validator
}

func NewAuth0Middleware(validator RequestJWTValidator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			token, err := validator.ValidateRequest(r)

			if err != nil {
				logger.WithFields(logrus.Fields{
					"user_ip": r.RemoteAddr,
					"url":     r.URL,
					"error":   err,
					"token":   token,
				}).Warning("token is not valid")

				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized"))
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
