#!/bin/bash

# OpenWatch FIPS-Compliant Certificate Generation Script
# This script generates self-signed certificates for development and testing
# For production, use certificates from a trusted Certificate Authority

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CERT_DIR="${CERT_DIR:-./security/certs}"
KEY_SIZE=4096
DAYS_VALID=365
COUNTRY="US"
STATE="MD"
CITY="Baltimore"
ORGANIZATION="Hanalyx"
ORGANIZATIONAL_UNIT="OpenWatch"
COMMON_NAME="localhost"

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    print_error "OpenSSL is not installed. Please install OpenSSL first."
    exit 1
fi

# Check OpenSSL FIPS capability
print_info "Checking OpenSSL FIPS capability..."
if openssl version | grep -q "FIPS"; then
    print_info "OpenSSL FIPS module detected"
    FIPS_AVAILABLE=true
else
    print_warning "OpenSSL FIPS module not detected. Certificates will be generated without FIPS validation."
    FIPS_AVAILABLE=false
fi

# Create certificate directory
print_info "Creating certificate directory: $CERT_DIR"
mkdir -p "$CERT_DIR"

# Generate private key
print_info "Generating RSA private key (${KEY_SIZE} bits)..."
openssl genrsa -out "$CERT_DIR/server.key" $KEY_SIZE

# Set appropriate permissions for private key
chmod 600 "$CERT_DIR/server.key"

# Generate certificate signing request (CSR)
print_info "Generating Certificate Signing Request..."
openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=$COMMON_NAME"

# Generate self-signed certificate
print_info "Generating self-signed certificate (valid for $DAYS_VALID days)..."
openssl x509 -req -days $DAYS_VALID -in "$CERT_DIR/server.csr" -signkey "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt"

# Generate Diffie-Hellman parameters for enhanced security
print_info "Generating Diffie-Hellman parameters (this may take a while)..."
openssl dhparam -out "$CERT_DIR/dhparam.pem" 2048

# Create a combined certificate file (useful for some applications)
print_info "Creating combined certificate file..."
cat "$CERT_DIR/server.crt" "$CERT_DIR/server.key" > "$CERT_DIR/server.pem"
chmod 600 "$CERT_DIR/server.pem"

# Generate client certificates for mutual TLS (optional)
print_info "Generating client certificate for mutual TLS..."
openssl genrsa -out "$CERT_DIR/client.key" $KEY_SIZE
chmod 600 "$CERT_DIR/client.key"
openssl req -new -key "$CERT_DIR/client.key" -out "$CERT_DIR/client.csr" -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=client"
openssl x509 -req -days $DAYS_VALID -in "$CERT_DIR/client.csr" -signkey "$CERT_DIR/client.key" -out "$CERT_DIR/client.crt"

# Clean up CSR files
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/client.csr"

# Display certificate information
print_info "Certificate generation complete!"
echo ""
print_info "Generated files:"
echo "  - Server private key: $CERT_DIR/server.key"
echo "  - Server certificate: $CERT_DIR/server.crt"
echo "  - Server combined PEM: $CERT_DIR/server.pem"
echo "  - DH parameters: $CERT_DIR/dhparam.pem"
echo "  - Client private key: $CERT_DIR/client.key"
echo "  - Client certificate: $CERT_DIR/client.crt"
echo ""

# Display certificate details
print_info "Server certificate details:"
openssl x509 -in "$CERT_DIR/server.crt" -noout -text | grep -E "(Subject:|Issuer:|Not Before:|Not After:|Signature Algorithm:)" | sed 's/^/  /'

echo ""
print_warning "These are self-signed certificates for development use only!"
print_warning "For production, use certificates from a trusted Certificate Authority."

# Verify certificates
print_info "Verifying certificate integrity..."
if openssl x509 -in "$CERT_DIR/server.crt" -noout -text &> /dev/null; then
    print_info "Server certificate verification: PASSED"
else
    print_error "Server certificate verification: FAILED"
    exit 1
fi

if openssl x509 -in "$CERT_DIR/client.crt" -noout -text &> /dev/null; then
    print_info "Client certificate verification: PASSED"
else
    print_error "Client certificate verification: FAILED"
    exit 1
fi

print_info "All certificates generated and verified successfully!"
