# OpenWatch Security Directory

This directory contains TLS certificates and cryptographic keys for OpenWatch. **These files are not included in the repository for security reasons.**

## Directory Structure

```
security/
├── certs/          # TLS/SSL certificates
│   ├── ca.crt      # Certificate Authority certificate
│   ├── server.crt  # Server certificate
│   ├── server.key  # Server private key
│   └── client.crt  # Client certificate
└── keys/           # Application cryptographic keys
    ├── jwt_private.pem  # JWT signing private key
    ├── jwt_public.pem   # JWT verification public key
    └── *.key           # Other application keys
```

## Setup Instructions

### 1. Generate TLS Certificates

For development:
```bash
# Run the certificate generation script
./scripts/generate-certs.sh
```

For production:
- Use certificates from a trusted Certificate Authority
- Place certificates in the appropriate directories
- Ensure proper file permissions (600 for private keys, 644 for certificates)

### 2. Generate JWT Keys

```bash
# Generate RSA key pair for JWT signing
openssl genrsa -out security/keys/jwt_private.pem 2048
openssl rsa -in security/keys/jwt_private.pem -pubout -out security/keys/jwt_public.pem

# Set proper permissions
chmod 600 security/keys/jwt_private.pem
chmod 644 security/keys/jwt_public.pem
```

### 3. File Permissions

Ensure proper file permissions for security:

```bash
# Private keys - read/write for owner only
chmod 600 security/keys/*.pem
chmod 600 security/keys/*.key
chmod 600 security/certs/*.key

# Certificates - read for owner and group
chmod 644 security/certs/*.crt
chmod 644 security/certs/*.pem
```

### 4. Container Volume Mounts

The security directory is mounted into containers at `/app/security/`:

```yaml
volumes:
  - ./security/keys:/app/security/keys:ro
  - ./security/certs:/app/security/certs:ro
```

## Security Best Practices

1. **Never commit private keys or certificates to version control**
2. **Use strong, randomly generated passwords and keys**
3. **Rotate certificates and keys regularly**
4. **Monitor access to security files**
5. **Use proper file system permissions**
6. **Consider using a dedicated secrets management system for production**

## Certificate Management

### Self-Signed Certificates (Development)

The `generate-certs.sh` script creates self-signed certificates suitable for development. These should **never be used in production**.

### Production Certificates

For production deployments:

1. **Obtain certificates from a trusted CA**
2. **Use proper domain validation**
3. **Implement certificate renewal automation**
4. **Monitor certificate expiration**

### Certificate Verification

Verify certificate details:

```bash
# Check certificate information
openssl x509 -in security/certs/server.crt -text -noout

# Verify certificate chain
openssl verify -CAfile security/certs/ca.crt security/certs/server.crt

# Check key pair matching
openssl x509 -noout -modulus -in security/certs/server.crt | openssl md5
openssl rsa -noout -modulus -in security/certs/server.key | openssl md5
```

## Troubleshooting

### Common Issues

1. **Permission denied errors**: Check file permissions
2. **Certificate verification failures**: Verify certificate chain
3. **Key mismatch errors**: Ensure certificate and private key match
4. **JWT signing errors**: Verify JWT key format and permissions

### Debug Commands

```bash
# Check certificate expiration
openssl x509 -in security/certs/server.crt -noout -dates

# Test TLS connection
openssl s_client -connect localhost:443 -servername localhost

# Verify JWT key format
openssl rsa -in security/keys/jwt_private.pem -check
```

---

**Security Notice**: This directory contains sensitive cryptographic material. Ensure proper access controls and never expose these files publicly.
