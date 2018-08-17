package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth/limiter"
	"github.com/getsentry/raven-go"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"github.com/thisendout/apollo"
)

var (
	logger *logrus.Logger

	rootCtx context.Context
)

const (
	MB = 1 << (10 * 2)
)

// TODO: double-check the safety and need for the healthcheck endpoint?
// TODO security: limit request size?
// TODO add client-side caching instruction middleware (ETAGs and the like)
// TODO set (global?) sentry DSN
// TODO rate limiting to fewer than 1 req / second possible?
// TODO handle secrets (the only secret is now hardcoded in the tests)
// TODO additional checks on validity of config file (e.g. Uniqueness of endpoints?)
// TODO set the error log property for the reverse proxy func (see docs of httputil.ReverseProxy struct)
// TODO catch invalid token errors that may be caused by bad config and not malicious acting. These should go to sentry.
// TODO pull all handlers that log to the 'log' interface into logrus (e.g. CORS handlers and the net/http server object)
// TODO separate sublogger per endpoint

// TODO inject below vars via environment
const (
	JWKS_URI                     = $REDACTED
	DEFAULT_CONFIG_FILE_LOCATION = "./config.json"
	HEALTHCHECK_ENDPOINT         = "/healthz"
)

var (
	auth0Domain   = $REDACTED
	auth0Audience = $REDACTED
)

// For Apollo (see also Alice), your middleware constructors should have the form of "func (http.Handler) http.Handler"
// Some middleware provide this out of the box, Sentry doesn't. Note that this handler is independent of
// the application StateHolder, and as such implements a separate Sentry client..
func myRecoveryHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(raven.RecoveryHandler(next.ServeHTTP))
}

// NewServer is the generator for the fully configured custom server object, for easier testing.
func NewServer(port string) *http.Server {
	return &http.Server{
		Addr: port,

		//You should set Read, Write and Idle timeouts when dealing with untrusted clients and/or networks, so that a client can't hold up a connection by being slow to write or read.
		// An interesting (albeit slightly outdated) read regarding hardening Go HTTP servers for the open internet: https://blog.cloudflare.com/exposing-go-on-the-internet/
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 * MB,
	}
}

func NewRootMiddlewareChain(ctx context.Context) apollo.Chain {
	// build the middleware chain.
	// Apollo provides a Wrap function to inject normal http.Handler-based middleware into the chain.
	// The context will skip over the injected middleware and pass unharmed to the next context-aware handler in the chain.
	chain := apollo.New(apollo.Wrap(myRecoveryHandler)).With(ctx)
	return chain
}

type CorsOptions struct {
	AllowedOrigins     []string
	AllowedMethods     []string
	AllowedHeaders     []string
	ExposedHeaders     []string
	AllowCredentials   bool
	MaxAge             int
	OptionsPassthrough bool
	Debug              bool
}

func (c CorsOptions) ToConfig() cors.Options {
	return cors.Options{
		AllowedOrigins:     c.AllowedOrigins,
		AllowedMethods:     c.AllowedMethods,
		AllowedHeaders:     c.AllowedHeaders,
		ExposedHeaders:     c.ExposedHeaders,
		AllowCredentials:   c.AllowCredentials,
		MaxAge:             c.MaxAge,
		OptionsPassthrough: c.OptionsPassthrough,
		Debug:              c.Debug,
	}
}

type APIDeclaration struct {
	Name               string
	TargetURL          string
	Prefix             string
	StripPrefix        bool
	Auth               bool
	RateLimitPerSecond int64
	Gzip               bool
	CORS               *CorsOptions
}

func (a APIDeclaration) Serialize() ([]byte, error) {
	serializedSettings, err := json.Marshal(a)
	return serializedSettings, err
}

func GetAndValidateConfig(configFilePath string) []APIDeclaration {
	file, err := os.Open(configFilePath)
	if err != nil {
		logger.WithError(err).Fatal("could not open or find config file at %v", configFilePath)
	}

	configBytes, err := ioutil.ReadAll(file)
	if err != nil {
		logger.WithError(err).Fatal("error ingesting config file")
	}

	var declarations []APIDeclaration
	err = json.Unmarshal(configBytes, &declarations)
	if err != nil {
		logger.WithError(err).Fatal("Error unmarshalling config file: ", err)
	}

	// check if the healthcheck endpoint has been accidentally overridden
	for _, a := range declarations {
		if a.Prefix == HEALTHCHECK_ENDPOINT {
			logger.Fatalf("Endpoint name %v already taken by healthcheck endpoint!")
		}
	}

	return declarations
}

func reverseProxyHandler(reverseProxyFunc *httputil.ReverseProxy) apollo.HandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		reverseProxyFunc.ServeHTTP(w, r)
	}
}

func NewLoggerMiddleware(logger *logrus.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			logger.WithFields(logrus.Fields{
				"user_ip": r.RemoteAddr,
				"url":     r.URL,
				"headers": r.Header,
			}).Info("received request")

			next.ServeHTTP(w, r)
		})
	}
}

func buildServeMux(rootChain apollo.Chain, apis []APIDeclaration, validator RequestJWTValidator) *http.ServeMux {
	// build the serve mux (the collection of handler functions)
	mux := http.NewServeMux()

	for _, api := range apis {

		customChain := rootChain

		// add logging middleware
		customChain = customChain.Append(apollo.Wrap(NewLoggerMiddleware(logger)))

		// add handling of CORS-related preflight requests
		// We dont want these requests to be rate limited
		if api.CORS != nil {
			corsHandler := cors.New(api.CORS.ToConfig())

			// set a logger for the corsHandler
			corsHandler.Log = log.New(os.Stdout, "preflight", 1)

			customChain = customChain.Append(apollo.Wrap(corsHandler.Handler))
		}

		// set the ratelimit to a default if not available
		var rl int64
		rl = 1
		if api.RateLimitPerSecond != 0 {
			rl = api.RateLimitPerSecond
		}

		// add rate limiter
		// build a rate limiter middleware function
		// by default it keys the limiter on the following headers: "RemoteAddr", "X-Forwarded-For", "X-Real-IP"
		// create a 1 request/second limiter and every token bucket in it will expire 1 hour after it was initially set.
		lmt := tollbooth.NewLimiter(rl, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
		lmt.SetOnLimitReached(func(w http.ResponseWriter, r *http.Request) {
			logger.WithFields(logrus.Fields{
				"user_ip": r.RemoteAddr,
				"url":     r.URL,
			}).Info("rate limit exceeded")
			return
		})

		// wrap the rate limiter for use in Apollo chains
		wrappedRateLimiter := func(next http.Handler) http.Handler { return tollbooth.LimitHandler(lmt, next) }

		// add the rate limiter to the main chain
		customChain = customChain.Append(apollo.Wrap(wrappedRateLimiter))

		// add auth middleware if required
		if api.Auth {
			customChain = customChain.Append(apollo.Wrap(NewAuth0Middleware(validator)))
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

		// wrap the reverse proxy into a handler (so it implements to apollo.Handler) and append it to the chain
		mux.Handle(api.Prefix, customChain.Then(reverseProxyHandler(reverseProxyFunc)))

	}

	// Register the healthcheck endpoint
	mux.Handle(HEALTHCHECK_ENDPOINT, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		return
	}))

	return mux
}

func init() {

	// initiate a logger and point it to Stdout (for Docker)
	logger = logrus.New()
	logger.Out = os.Stdout

	// Log as JSON instead of the default ASCII formatter.
	logger.Formatter = &logrus.JSONFormatter{}
}

func main() {

	logger.Info("Initiating gateway...")

	// init the background context
	rootCtx = context.Background()

	// build the root middleware chain
	rootChain := NewRootMiddlewareChain(rootCtx)

	// find out which config file we are supposed to watch
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		logger.Warn("Config file not set via environment variable. Defaulting to %v", DEFAULT_CONFIG_FILE_LOCATION)
		configFile = DEFAULT_CONFIG_FILE_LOCATION
	}

	// get targets and settings from JSON
	apis := GetAndValidateConfig(configFile)

	if len(apis) == 0 {
		logger.Fatal("No API proxying settings found in config file.")
	}

	// log api settings
	for _, a := range apis {
		serializedSettings, err := a.Serialize()
		if err != nil {
			logger.WithError(err).Fatal("Error re-serializing API config: ", err)
		}
		logger.WithFields(logrus.Fields{
			"settings": string(serializedSettings),
		}).Infof("Settings for endpoint %v", a.Name)
	}

	// initiate the Auth0 JWT validator object
	validator := NewAuth0Validator()

	// collect the handlers for each API in a mux
	mux := buildServeMux(rootChain, apis, validator)

	// instantiate the server
	httpSrv := NewServer(":8080")

	// add the mux to the server
	httpSrv.Handler = mux

	logger.Infof("Starting the HTTP server at port %v", httpSrv.Addr)

	// start the server
	log.Fatal(httpSrv.ListenAndServe())
}
