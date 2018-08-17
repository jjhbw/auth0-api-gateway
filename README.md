An initial version of an API gateway I wrote. 

This prototype contained several hardcoded URL's which I had to redact, as from here on the continued development of this project was considered proprietary.

**Summary**

- Endpoints are configured using a simple JSON file
- Features simple JWT-based authentication using [Auth0](http://auth0.com/) integration
- Most of the heavy lifting is done by Go's brilliant HTTP standard library
- It uses a docker multi-stage build to create a minimalist docker image