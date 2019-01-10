####--- build stage
FROM golang:1.11.4 AS build-env

WORKDIR building

# Copy the app
ADD . .

# Build a static binary from the server code, disabling CGO and the like.
# NOTE: if you want to use the vendor directory, provide the `-mod=vendor` flag.
RUN CGO_ENABLED=0 GOOS=linux go build -v -ldflags '-w -s' -a -installsuffix cgo -o /server_binary

# For HTTPS: update the CA certificates which we will copy to the runtime container aswell
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

####--- runtime stage
FROM scratch

# copy the CA certificates from the builder
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# get the compiled binary from the first build stage
COPY --from=build-env /server_binary .

# run the server binary on container startup
CMD ["./server_binary"]
