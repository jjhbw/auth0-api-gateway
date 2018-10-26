package main

import (
	"compress/gzip"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth/limiter"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"github.com/thisendout/apollo"
)

func buildServeMux(rootChain apollo.Chain, settings GatewaySettings) *http.ServeMux {
	// build the serve mux (the collection of handler functions)
	mux := http.NewServeMux()

	for _, api := range settings.APIConfigs {

		customChain := rootChain

		// add rate limiter
		if api.RateLimitPerSecond != 0 {
			rl := api.RateLimitPerSecond

			// build a rate limiter middleware function
			// by default it keys the limiter on the following headers: "RemoteAddr", "X-Forwarded-For", "X-Real-IP"
			// create an X request/second limiter and every token bucket in it will expire 1 hour after it was initially set.
			lmt := tollbooth.NewLimiter(rl, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})

			// trigger a custom function with some logging info when the limit is reached
			lmt.SetOnLimitReached(func(w http.ResponseWriter, r *http.Request) {
				logger.WithFields(logrus.Fields{
					"remote_ip":      r.RemoteAddr,
					"url":            r.URL.String(),
					"max_per_second": rl,
				}).Info("rate limit exceeded")
				return
			})

			// We override the default headers that are inspected to avoid that requests coming from CloudFlare (or some other CDN)
			// edge servers are considered as coming from the same user.
			// We avoid this by setting the RemoteAddr lookup last. This ensures it is only used when none of the other headers are available.
			lmt.SetIPLookups([]string{"X-Forwarded-For", "X-Real-IP", "RemoteAddr"})

			// Make sure the HTTP method is involved in the generation of the rate limit key so
			// the CORS preflight OPTIONS requests do not trigger a rate limit for the subsequent real request.
			lmt.SetMethods([]string{
				http.MethodGet,
				http.MethodHead,
				http.MethodPost,
				http.MethodPut,
				http.MethodPatch,
				http.MethodDelete,
				http.MethodConnect,
				http.MethodOptions,
				http.MethodTrace,
			})

			// wrap the rate limiter for use in Apollo chains
			wrappedRateLimiter := func(next http.Handler) http.Handler { return tollbooth.LimitHandler(lmt, next) }

			// add the rate limiter to the main chain
			customChain = customChain.Append(apollo.Wrap(wrappedRateLimiter))

		}

		// Add the access logging middleware
		customChain = customChain.Append(apollo.Wrap(NewLoggerMiddleware(logger)))

		// add handling of CORS-related preflight requests.
		if api.CORS != nil {
			corsHandler := cors.New(api.CORS.ToConfig())

			// TODO: default logger is way too verbose. Leave it to our own access Logger.
			// // set a logger for the corsHandler.
			// // Derive this logger from logrus. We consider all these log entries 'INFO'.
			// corsLogger := logger.WriterLevel(logrus.InfoLevel)
			// corsHandler.Log = log.New(corsLogger, "cors_preflight--", 0)

			customChain = customChain.Append(apollo.Wrap(corsHandler.Handler))
		}

		// add auth middleware if required
		if api.Auth {
			customChain = customChain.Append(apollo.Wrap(NewJWTMiddleware(settings.requestAuthenticator)))
		}

		// add the gzip middleware if required
		if api.Gzip {
			gz := gziphandler.MustNewGzipLevelHandler(gzip.DefaultCompression)
			customChain = customChain.Append(apollo.Wrap(gz))
		}

		if api.StripPrefix {
			// Apollo provides a Wrap function to inject normal http.Handler-based middleware into the chain.
			// The context will skip over the injected middleware and pass unharmed to the next context-aware handler in the chain.
			customChain = customChain.Append(apollo.Wrap(func(next http.Handler) http.Handler { return http.StripPrefix(api.Prefix, next) }))
		}

		// parse the target URL
		target, err := url.Parse(api.TargetURL)
		if err != nil {
			logger.WithError(err).Fatalf("could not parse url : %v", api.TargetURL)
		}

		// parametrise the reverse proxy function
		reverseProxyFunc := httputil.NewSingleHostReverseProxy(target)

		// set a logger for the reverseProxyFunc, which only logs errors.
		// Derive this logger from logrus.
		revProxyLogger := logger.WriterLevel(logrus.ErrorLevel)
		reverseProxyFunc.ErrorLog = log.New(revProxyLogger, "reverseproxy--", 0)

		// wrap the reverse proxy into a handler (so it implements to apollo.Handler) and append it to the chain
		mux.Handle(api.Prefix, customChain.Then(reverseProxyHandler(reverseProxyFunc)))

	}

	return mux
}
