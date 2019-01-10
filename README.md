# Auth0 Gateway

Example of how to set up a reverse proxy in Golang  that can validate [Auth0](https://auth0.com/) JWT's.

**Summary**:

- Endpoints are configured using a simple JSON file
- Features JWT-based authentication using Auth0 integration
- Most of the heavy lifting is done by Go's brilliant HTTP standard library
- HTTPS: either through LetsEncrypt or by providing your own certificate and key.
- Optional TLS mutual auth (aimed at CloudFlare's authenticated origin pulls)
- CORS is configurable per endpoint
- Includes a Dockerfile specifying a multi-stage build to create a minimalist docker image



# Configuration

Configuration is done using the following environment variables:

```bash
# Endpoints to act as a reverse proxy for. See below or example_config.json
CONFIG_FILE=/config.json

# Auth0 config. See Auth0 documentation.
AUTH0_AUDIENCE="..."
JWKS_URI="..."
AUTH0_DOMAIN="..."

# Optional LetsEncrypt:
LETS_ENCRYPT_EMAIL=${your_email}
FULL_DOMAIN="..." #"FQDN where service will be reachable"
CERTIFICATE_PERSISTENCE_DIR=/certs

# Or if you have a certificate and key, specify the paths
TLS_CERT_PATH=certificate.pem
TLS_KEY_PATH=key.pem

# For TLS mutual auth
TLS_CLIENT_CA="..." # path to client CA e.g. CloudFlare's origin-pull-ca.pem
```

**Note** that the server by default binds to port `80` (and `443`  if `LETS_ENCRYPT_EMAIL` is set).

Endpoints are configured using an array of JSON objects.

```json5
[
  {
    "TargetURL" : "http://searchservice:8080",
    "Prefix": "/search",
    "StripPrefix": false,
    "Name" : "text query service",
    "Auth" : true, # whether to enable Auth0
    "RateLimitPerSecond": 0.5, # Supports floats. This case: 1 request each 2 seconds
    "Gzip": true,
    "CORS" : {
      "AllowedOrigins" : ["*.blabla.com"],
      "AllowCredentials" : true,
      "AllowedHeaders": ["Authorization", "Content-Type"]
    }
  }
]
```



# Testing

To run all local tests:

```bash
go test --short
```



## Auth0 integration testing

Note that this requires access to the Auth0 API.

For testing the Auth0 integration, ensure the following environment variables are set:

```bash
AUTH0_TESTING_URL="..."
AUTH0_CLIENT_ID="..."
AUTH0_CLIENT_SECRET="..."
AUTH0_AUDIENCE="..."
JWKS_URI="..."
AUTH0_DOMAIN="..."
```

The values for these settings can be found in the 'test' tab of the API settings on the Auth0 dashboard.
