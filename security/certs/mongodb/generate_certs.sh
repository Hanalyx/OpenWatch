#!/bin/bash
################################################################################
# MongoDB Certificate Generation Script
# Purpose: Generate new TLS certificates for MongoDB after security incident
# Generated: 2025-10-15
################################################################################

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAYS_VALID=3650  # 10 years
BACKUP_DIR="${CERT_DIR}/backup-$(date +%Y%m%d-%H%M%S)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}MongoDB Certificate Generation${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Backup existing certificates
if [ -f "${CERT_DIR}/mongodb.pem" ]; then
    echo -e "${YELLOW}⚠️  Backing up existing certificates...${NC}"
    mkdir -p "${BACKUP_DIR}"
    cp "${CERT_DIR}"/*.{pem,crt,key} "${BACKUP_DIR}/" 2>/dev/null || true
    echo -e "${GREEN}✅ Backup created: ${BACKUP_DIR}${NC}"
    echo ""
fi

# Generate CA Certificate (Certificate Authority)
echo -e "${BLUE}📝 Generating CA certificate...${NC}"
openssl genrsa -out "${CERT_DIR}/ca.key" 4096
openssl req -new -x509 -days ${DAYS_VALID} -key "${CERT_DIR}/ca.key" \
    -out "${CERT_DIR}/ca.crt" \
    -subj "/C=US/ST=State/L=City/O=OpenWatch/OU=Security/CN=OpenWatch MongoDB CA" \
    -sha256

echo -e "${GREEN}✅ CA certificate generated${NC}"

# Generate Server Certificate
echo -e "${BLUE}📝 Generating server certificate...${NC}"
openssl genrsa -out "${CERT_DIR}/server.key" 4096
openssl req -new -key "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.csr" \
    -subj "/C=US/ST=State/L=City/O=OpenWatch/OU=Security/CN=mongodb.openwatch.local" \
    -sha256

# Create v3 extensions file for SAN (Subject Alternative Names)
cat > "${CERT_DIR}/server.v3.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = mongodb
DNS.2 = mongodb.openwatch.local
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

# Sign server certificate
openssl x509 -req -days ${DAYS_VALID} \
    -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/server.crt" \
    -extfile "${CERT_DIR}/server.v3.ext" \
    -sha256

# Create combined PEM file for MongoDB
cat "${CERT_DIR}/server.key" "${CERT_DIR}/server.crt" > "${CERT_DIR}/mongodb.pem"

# Keep separate files for backward compatibility
cp "${CERT_DIR}/server.key" "${CERT_DIR}/mongodb.key"
cp "${CERT_DIR}/server.crt" "${CERT_DIR}/mongodb.crt"

echo -e "${GREEN}✅ Server certificate generated${NC}"

# Generate Client Certificate
echo -e "${BLUE}📝 Generating client certificate...${NC}"
openssl genrsa -out "${CERT_DIR}/client.key" 4096
openssl req -new -key "${CERT_DIR}/client.key" \
    -out "${CERT_DIR}/client.csr" \
    -subj "/C=US/ST=State/L=City/O=OpenWatch/OU=Security/CN=mongodb-client" \
    -sha256

openssl x509 -req -days ${DAYS_VALID} \
    -in "${CERT_DIR}/client.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/client.crt" \
    -sha256

echo -e "${GREEN}✅ Client certificate generated${NC}"

# Set proper permissions
echo -e "${BLUE}🔒 Setting secure permissions...${NC}"
chmod 600 "${CERT_DIR}"/*.key "${CERT_DIR}"/*.pem
chmod 644 "${CERT_DIR}"/*.crt

# Clean up temporary files
rm -f "${CERT_DIR}"/*.csr "${CERT_DIR}"/*.srl "${CERT_DIR}"/*.v3.ext

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ Certificate Generation Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Display certificate information
echo -e "${BLUE}📋 Certificate Details:${NC}"
echo ""
echo -e "${YELLOW}CA Certificate:${NC}"
openssl x509 -in "${CERT_DIR}/ca.crt" -noout -subject -dates
echo ""
echo -e "${YELLOW}Server Certificate:${NC}"
openssl x509 -in "${CERT_DIR}/server.crt" -noout -subject -dates -ext subjectAltName
echo ""
echo -e "${YELLOW}Client Certificate:${NC}"
openssl x509 -in "${CERT_DIR}/client.crt" -noout -subject -dates
echo ""

# List generated files
echo -e "${BLUE}📁 Generated Files:${NC}"
ls -lh "${CERT_DIR}"/*.{pem,crt,key} 2>/dev/null | awk '{print $9, $5}'
echo ""

# Important notes
echo -e "${YELLOW}⚠️  IMPORTANT SECURITY NOTES:${NC}"
echo ""
echo "1. These certificates are SELF-SIGNED and suitable for:"
echo "   - Development environments"
echo "   - Internal MongoDB clusters"
echo "   - Testing purposes"
echo ""
echo "2. For PRODUCTION, consider:"
echo "   - Using certificates from a trusted CA"
echo "   - Implementing certificate rotation policies"
echo "   - Setting up automated certificate renewal"
echo ""
echo "3. These files are GITIGNORED - DO NOT commit to version control!"
echo "   - Private keys: *.key, *.pem"
echo "   - Check .gitignore for confirmation"
echo ""
echo "4. Next steps:"
echo "   - Update MongoDB configuration to use new certificates"
echo "   - Restart MongoDB service/containers"
echo "   - Update application connection strings if needed"
echo "   - Verify MongoDB accepts connections with new certs"
echo ""
echo -e "${GREEN}Old certificates backed up to:${NC}"
echo "   ${BACKUP_DIR}"
echo ""
echo -e "${BLUE}To verify certificates are gitignored:${NC}"
echo "   git check-ignore ${CERT_DIR}/*.pem"
echo ""

# Generate certificate rotation log entry
LOG_FILE="${CERT_DIR}/../../CERTIFICATE_ROTATION_LOG.md"
if [ ! -f "$LOG_FILE" ]; then
    cat > "$LOG_FILE" << 'EOFLOG'
# Certificate Rotation Log

## Purpose
This log tracks all certificate generation and rotation events for OpenWatch security infrastructure.

---

EOFLOG
fi

cat >> "$LOG_FILE" << EOFLOGENTRY

## $(date +%Y-%m-%d): MongoDB Certificate Rotation

**Reason:** Security incident - private key committed to git history

**Action:** Generated new self-signed certificates
- CA Certificate: 10-year validity
- Server Certificate: 10-year validity with SAN support
- Client Certificate: 10-year validity

**Generated Files:**
- ca.crt, ca.key
- server.crt, server.key
- client.crt, client.key
- mongodb.pem (combined server key + cert)

**Backup Location:** ${BACKUP_DIR}

**Generated By:** $(whoami)
**Timestamp:** $(date)

**Next Actions:**
- [ ] Update MongoDB container configuration
- [ ] Restart MongoDB services
- [ ] Test MongoDB connectivity
- [ ] Remove old certificate from git tracking
- [ ] Update documentation

---
EOFLOGENTRY

echo -e "${GREEN}✅ Rotation logged to: ${LOG_FILE}${NC}"
echo ""
echo -e "${GREEN}Certificate generation complete!${NC}"
