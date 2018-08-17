####--- build stage
FROM golang:1.10 AS build-env

# ensure GOPATH is properly set up
RUN  mkdir -p /go/src \
  && mkdir -p /go/bin \
  && mkdir -p /go/pkg
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

# now copy the app to the proper build path
RUN mkdir -p $GOPATH/src/gitlab.com/redacted/gateway
ADD . $GOPATH/src/gitlab.com/redacted/gateway

WORKDIR $GOPATH/src/gitlab.com/redacted/gateway

# Build a static binary from the server code, disabling CGO and the like.
RUN CGO_ENABLED=0 GOOS=linux go build -v -ldflags '-w -s' -a -installsuffix cgo -o /server_binary

# Compile the tests to a static binary
RUN CGO_ENABLED=0 GOOS=linux go test -c -ldflags '-w -s' -a -installsuffix cgo -o /server.test

####--- final stage
FROM alpine:latest

# add the ca root certis to allow the server to make HTTPS calls
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

WORKDIR /gateway

# copy the test binary from the build container
COPY --from=build-env /server.test /gateway/

# run the test binary (in verbose mode)
RUN /gateway/server.test -test.v

# clean up the test binary
RUN rm /gateway/server.test

# get the compiled binary from the first build stage
COPY --from=build-env /server_binary /gateway/

# run the server binary on container startup
CMD ["./server_binary"]