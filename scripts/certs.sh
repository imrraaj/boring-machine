# infra/scripts/gen-self-signed-cert.sh (example)
# openssl genrsa -out server.key 2048
# openssl req -new -x509 -key server.key -out server.crt -days 365 \
#   -subj "/CN=boring.rajpa.tel/O=local-dev"
go run $(go env GOROOT)/src/crypto/tls/generate_cert.go --host 127.0.0.1