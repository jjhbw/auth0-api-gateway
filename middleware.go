package main

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

func NewLoggerMiddleware(logger *logrus.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			logger.WithFields(logrus.Fields{
				"remote_ip": r.RemoteAddr,
				"url":       r.URL.String(),
				"headers":   r.Header,
			}).Info("received request")

			next.ServeHTTP(w, r)
		})
	}
}

func NewJWTMiddleware(validator JWTRequestValidator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			token, err := validator.ValidateRequest(r)

			if err != nil {
				logger.WithFields(logrus.Fields{
					"remote_ip": r.RemoteAddr,
					"url":       r.URL.String(),
					"error":     err,
					"token":     token,
				}).Warning("token is not valid")

				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized"))
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
