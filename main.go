package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"time"
	"crypto/x509"
	"crypto/tls"

	"golang.org/x/crypto/acme/autocert"

	"github.com/evalphobia/logrus_sentry"
	"github.com/getsentry/raven-go"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"github.com/thisendout/apollo"
)

var (
	logger  *logrus.Logger
	rootCtx context.Context
)

const (
	MB = 1 << (10 * 2)
)

// environment variable keys
const (
	JWKURIEnvKey        = "JWKS_URI"
	Auth0DomainEnvKey   = "AUTH0_DOMAIN"
	Auth0AudienceEnvKey = "AUTH0_AUDIENCE"
)

// For Apollo (see also Alice), your middleware constructors should have the form of "func (http.Handler) http.Handler"
// Some middleware provide this out of the box, Sentry doesn't. Note that this handler is independent of
// the application StateHolder, and as such implements a separate Sentry client..
func myRecoveryHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(raven.RecoveryHandler(next.ServeHTTP))
}

// NewServer is the generator for the fully configured custom server object, for easier testing.
func NewServer(port string, loggerDropIn *log.Logger) *http.Server {
	return &http.Server{
		Addr: port,

		//You should set Read, Write and Idle timeouts when dealing with untrusted clients and/or networks, so that a client can't hold up a connection by being slow to write or read.
		// An interesting (albeit slightly outdated) read regarding hardening Go HTTP servers for the open internet: https://blog.cloudflare.com/exposing-go-on-the-internet/
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 * MB,

		// http.Server only accepts the standard library's logger struct.
		ErrorLog: loggerDropIn,
	}
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
	RateLimitPerSecond float64
	Gzip               bool
	CORS               *CorsOptions
}

type GatewaySettings struct {
	APIConfigs           []APIDeclaration
	requestAuthenticator JWTRequestValidator
}

func (a APIDeclaration) Serialize() ([]byte, error) {
	serializedSettings, err := json.Marshal(a)
	return serializedSettings, err
}

func GetAndValidateConfig(configFilePath string) []APIDeclaration {
	file, err := os.Open(configFilePath)
	if err != nil {
		logger.WithError(err).Fatalf("could not open or find config file at %v", configFilePath)
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

	return declarations
}

func reverseProxyHandler(reverseProxyFunc *httputil.ReverseProxy) apollo.HandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		reverseProxyFunc.ServeHTTP(w, r)
	}
}

// get settings from the environment
func getSettingsFromEnv() GatewaySettings {
	// find out which config file we are supposed to watch
	configFile := getEnvOrFail("CONFIG_FILE")

	// get targets and settings from JSON
	apis := GetAndValidateConfig(configFile)

	if len(apis) == 0 {
		logger.Fatal("No API configurations found in config file.")
	}

	// log api settings
	for _, a := range apis {
		serializedSettings, err := a.Serialize()
		if err != nil {
			logger.WithError(err).Fatal("Error re-serializing API config for dumping in log stream.")
		}
		logger.WithFields(logrus.Fields{
			"settings": string(serializedSettings),
		}).Infof("Settings for endpoint %v", a.Name)
	}

	// get the Auth0 constants
	jwkURI := getEnvOrFail(JWKURIEnvKey)
	auth0Domain := getEnvOrFail(Auth0DomainEnvKey)
	auth0Audience := getEnvOrFail(Auth0AudienceEnvKey)

	// initiate the Auth0 JWT validator object
	validator := NewAuth0Validator(auth0Domain, jwkURI, []string{auth0Audience})

	return GatewaySettings{
		APIConfigs:           apis,
		requestAuthenticator: validator,
	}
}

func getEnvOrFail(envKey string) string {
	e := os.Getenv(envKey)
	if e == "" {
		logger.Fatalf("Critical environment variable %v not set. Terminating...", envKey)
	}
	return e
}

func newLetsEncryptManager(fullDomain, certificateDir, letsEncryptEmail string) *autocert.Manager {
	hostPolicy := func(ctx context.Context, host string) error {
		// Note: change to your real host
		allowedHost := fullDomain
		if host == allowedHost {
			return nil
		}
		return fmt.Errorf("acme/autocert: only %s host is allowed", allowedHost)
	}

	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache(certificateDir),
		Email:      letsEncryptEmail,
	}
}

// Generates two server objects:
// - plain HTTP server to handle HTTP -> HTTPS redirects.
// - TLS-enabled server to handle business logic.
func newTLSServerEnsemble(loggerDropIn *log.Logger, tlsConf *tls.Config) (*http.Server, *http.Server) {

	// initiate the server object
	httpsSrv := NewServer(":443", loggerDropIn)
	httpsSrv.TLSConfig = tlsConf

	// also initiate a plain HTTP server which we will use for redirects to the HTTPS one.
	plainHTTPSrv := NewServer(":80", loggerDropIn)

	// set the handler in the plainHTTPSrv server to a redirection function.
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		newURI := "https://" + r.Host + r.URL.String()
		http.Redirect(w, r, newURI, http.StatusFound)
	}
	redirectHandler := &http.ServeMux{}
	redirectHandler.HandleFunc("/", handleRedirect)
	plainHTTPSrv.Handler = redirectHandler

	return httpsSrv, plainHTTPSrv

}

// Build a base TLS config using the best-practices suggested by CloudFlare
func newTLSbaseConfig() *tls.Config {
	config := &tls.Config{
	// Causes servers to use Go's default ciphersuite preferences,
	// which are tuned to avoid attacks. Does nothing on clients.
	PreferServerCipherSuites: true,
	// Only use curves which have assembly implementations
	CurvePreferences: []tls.CurveID{
		tls.CurveP256,
		tls.X25519, // Go 1.8+ only
	},
		MinVersion: tls.VersionTLS12, // require at least TLS 1.2
		CipherSuites: []uint16{
			// Only the protocols that make SSL labs happy.
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8+ only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8+ only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Best disabled, as they don't provide Forward Secrecy,
			// but might be necessary for some clients
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	return config
}

func newRegularTLSConfig(certPath, keyPath string) *tls.Config {
	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		logger.Fatal(err)
	}

	config := newTLSbaseConfig()

	// add the certificates
	config.Certificates= []tls.Certificate{cer}

	return config
}

func newMutualAuthTLSConfig(certPath, keyPath, clientCertPath string) *tls.Config {
	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		logger.Fatal(err)
	}
	caCert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		logger.Fatal(err)
	}
	clientCACertPool := x509.NewCertPool()
	clientCACertPool.AppendCertsFromPEM(caCert)

	// build a 'regular' TLS configuration
	config := newRegularTLSConfig(certPath, keyPath)

	// add the certificates
	config.Certificates= []tls.Certificate{cer}

	// limit the CA's accepted to this exact pool
	config.ClientCAs= clientCACertPool

	// demand a client certificate
	config.ClientAuth = tls.RequireAndVerifyClientCert

	// Use CommonName and SubjectAlternateName of the certificates to build NameToCertificate.
	// NameToCertificate maps from a certificate name to an element of Certificates to use for a connection.
	config.BuildNameToCertificate()

	return config
}


func startTLSEnsemble(businessLogicMux *http.ServeMux, tlsServer, redirectServer *http.Server){
	// add the business logic handler mux to the tlsServer
	tlsServer.Handler = businessLogicMux

	// run the plain HTTP redirection server in a separate goroutine.
	go func() {
		logger.Infof("Starting plain HTTP redirection server on %v", redirectServer.Addr)
		err := redirectServer.ListenAndServe()
		if err != nil {
			logger.Fatalf("Starting plain HTTP redirection server failed with %v", err)
		}
	}()

	// run the primary HTTPS in the main thread
	// note that they key and certfiles will be provided by Autocert.
	logger.Infof("Starting HTTPS server on %v", tlsServer.Addr)
	err := tlsServer.ListenAndServeTLS("", "")
	if err != nil {
		logger.Fatalf("ListendAndServeTLS() failed with %v", err)
	}
}

func init() {

	// initiate a logger and point it to stdout
	logger = logrus.New()
	logger.Out = os.Stdout

	// Log as JSON instead of the default ASCII formatter.
	logger.Formatter = &logrus.JSONFormatter{}
}

func main() {

	logger.Info("Initiating gateway...")

	// get the global settings
	settings := getSettingsFromEnv()

	// get the Sentry DSN, if any.
	sentryDSN := os.Getenv("SENTRY_DSN")

	// explicitly set the Sentry DSN for use in the RecoveryHandler (the recovery handler uses the global sentry client).
	if len(sentryDSN) == 0 {
		logger.Error("SENTRY DSN NOT SET! global reporting (e.g. RecoveryHandler) disabled. ")
	} else {
		// set the Sentry DSN globally
		raven.SetDSN(sentryDSN)

		// build a logrus hook that feeds to Sentry.
		hook, err := logrus_sentry.NewSentryHook(sentryDSN, []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
			logrus.WarnLevel,
		})

		if err != nil {
			logger.Fatal("could not set logrus Sentry hook.", err)
		}
		logger.Hooks.Add(hook)
		logger.Infof("Sentry DSN set at URL: %v", raven.URL())
	}

	// init the background context
	rootCtx = context.Background()

	// build the root middleware chain
	// Apollo provides a Wrap function to inject normal http.Handler-based middleware into the chain.
	// The context will skip over the injected middleware and pass unharmed to the next context-aware handler in the chain.
	rootChain := apollo.New(apollo.Wrap(myRecoveryHandler)).With(rootCtx)

	// collect the handlers for each API in a multiplexer (mux)
	mux := buildServeMux(rootChain, settings)

	// Derive an io.Writer from the logrus logger to direct the logs of the stdlib's 'log' package-level logger to.
	// Note that we consider everything written to this sink an Info message.
	// I considered making them Error messages, but then web crawler activity failing TLS handshakes would pollute the Sentry log.
	serverObjectErrorSink := logger.WriterLevel(logrus.InfoLevel)
	defer serverObjectErrorSink.Close()

	// Note that `log` here references stdlib's log
	// Not logrus imported under the name `log`.
	loggerDropIn := log.New(serverObjectErrorSink, "http.Server--", 0)

	// TLS configuration depends on presence of these environment variables:
	letsEncryptEmail := os.Getenv("LETS_ENCRYPT_EMAIL")
	tlsCertPath := os.Getenv("TLS_CERT_PATH")
	tlsKeyPath := os.Getenv("TLS_KEY_PATH")
	tlsClientCAPath := os.Getenv("TLS_CLIENT_CA")

	// check if we want to configure letsencrypt or a regular TLS setup.
	var tlsServer *http.Server
	var redirectServer *http.Server

	if letsEncryptEmail != "" {

		// grab the domain name the server is publicly accessible on from env(for the LetsEncrypt webhook)
		fqdn := getEnvOrFail("FULL_DOMAIN")

		logger.Infof("Letsencrypt email provided. Starting LetsEncrypt-based HTTPS server on %v", fqdn)

		// where to persist the certificate to prevent unnecessary calls to LE (calls are limited to 20 per week anyway).
		certPersistenceDir := getEnvOrFail("CERTIFICATE_PERSISTENCE_DIR")

		// Build the main server object and the HTTP->HTTPS redirect server.
		// The LE Manager is a stateful certificate manager built on top of acme.Client.
		// It obtains and refreshes certificates automatically
		leManager := newLetsEncryptManager(fqdn, certPersistenceDir, letsEncryptEmail)
		tlsConf := &tls.Config{GetCertificate: leManager.GetCertificate}
		tlsServer, redirectServer = newTLSServerEnsemble(loggerDropIn, tlsConf)

		// Allow autocert handle Let's Encrypt auth callbacks over HTTP.
		// It will pass all urls unrelated to ACME validation to the existing redirect handler.
		redirectServer.Handler = leManager.HTTPHandler(redirectServer.Handler)

		startTLSEnsemble(mux, tlsServer, redirectServer)

	} else if tlsCertPath != "" {
		// in case a certificate and key path are provided: start a regular TLS server.
		if tlsKeyPath == "" {
			logger.Fatalf("Certificate is provided at %v, but no key isprovided using %v", tlsCertPath, tlsKeyPath)
		}

		var tlsConf *tls.Config
		if tlsClientCAPath != ""{
			logger.Info("TLS certificate, key and client CA provided. Starting mutual auth TLS server.")
			tlsConf = newMutualAuthTLSConfig(tlsCertPath, tlsKeyPath, tlsClientCAPath)
		}else{
			logger.Info("TLS certificate and key provided. No client CA provided. Starting regular, non-mutual TLS server.")
			tlsConf = newRegularTLSConfig(tlsCertPath, tlsKeyPath)
		}

		tlsServer, redirectServer = newTLSServerEnsemble(loggerDropIn, tlsConf)

		startTLSEnsemble(mux, tlsServer, redirectServer)

	} else {
		// instantiate a simple HTTP server object
		httpSrv := NewServer(":80", loggerDropIn)

		// add the mux to the server
		httpSrv.Handler = mux

		logger.Warningf("Starting the HTTP server at port %v", httpSrv.Addr)

		// start the server
		log.Fatal(httpSrv.ListenAndServe())
	}

}
