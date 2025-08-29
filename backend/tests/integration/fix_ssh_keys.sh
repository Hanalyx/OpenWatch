#!/bin/bash

# Script to deploy SSH public key to all reachable hosts
# This will enable SSH key authentication for hosts with auth_method='default'

SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYfxqzocYKHFaylpTuI7yg9u/DL8QEk8UtJz3FXfi87/KzOTPBhsqEZCErTzQ89OmQazkbzct5BI9MsHqnpH+lSxogkwr6UXNkiicP0/oha6xpOLnAe1j3cpry3GDB4Y4CtQMfKVL6i+iqAUJEr7DdcAI99oJGJjG+92IjYRrjY9pTHNmXGBPJJVoNvPQgR4WiE5UKQp+Av3RKmcaDGU7qR7Td1JJOxuCiJsZv0lJ49EdpLI75/2fxklxoEixq1junctsuQosxHva2EdHYJZGqgVbBpukvRqRh8fAYZm2d+nOOmbstwTVmC/ELSCyMSYrLGvh9KD/7ac7gM2KKZWfHwZt3TEKF+qYKD8uqcyYmzVrIeK+MlLt7P7P/DKqZnFUfJxXO1/mL6a5oNBjiyhmvH3wRbvcTpcKHsv21ge4JzBiW8IyyYKZEWAhYlS0xPMIREHuCnVr+dTUjoP5lhoo02mi1P/6ILXJwaTfyE8iJkgICnV3YMtfFYd3c8lDAbF8= owadmin@localhost.localdomain"

PASSWORD="@IZ=+RusuRespO0L"
USERNAME="owadmin"

# List of reachable hosts from database
HOSTS=(
    "192.168.1.212"  # owas-ub4m1.hanalyx.local
    "192.168.1.217"  # owas-ub5s2.hanalyx.local  
    "192.168.1.205"  # owas-tst02.hanalyx.local
    "192.168.1.203"  # owas-tst01.hanalyx.local
    "192.168.1.214"  # owas-ub4m2.hanalyx.local
    "192.168.1.213"  # owas-rhn02.hanalyx.local
    "192.168.1.211"  # owas-rhn01.hanalyx.local
)

echo "Starting SSH key deployment to ${#HOSTS[@]} hosts..."
echo "Public key fingerprint: $(echo "$SSH_PUBLIC_KEY" | ssh-keygen -lf - | cut -d' ' -f2)"

successful_hosts=0
failed_hosts=0

for host in "${HOSTS[@]}"; do
    echo ""
    echo "Processing host: $host"
    
    # Test if we can connect with password
    if sshpass -p "$PASSWORD" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$USERNAME@$host" "echo 'Password auth works'" &>/dev/null; then
        echo "  ✓ Password authentication successful"
        
        # Check if SSH directory exists and create if needed
        echo "  → Ensuring .ssh directory exists..."
        sshpass -p "$PASSWORD" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$USERNAME@$host" "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
        
        # Check if public key is already present
        key_present=$(sshpass -p "$PASSWORD" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$USERNAME@$host" "grep -c 'owadmin@localhost.localdomain' ~/.ssh/authorized_keys 2>/dev/null || echo 0")
        
        if [ "$key_present" -gt 0 ]; then
            echo "  ✓ SSH public key already present"
        else
            echo "  → Adding SSH public key to authorized_keys..."
            sshpass -p "$PASSWORD" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$USERNAME@$host" "echo '$SSH_PUBLIC_KEY' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
            echo "  ✓ SSH public key added"
        fi
        
        # Test SSH key authentication
        if ssh -i /home/rracine/workspace/compliance-suite/rsa_private_key -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$USERNAME@$host" "echo 'SSH key auth works'" &>/dev/null; then
            echo "  ✅ SSH key authentication successful"
            ((successful_hosts++))
        else
            echo "  ❌ SSH key authentication failed"
            ((failed_hosts++))
        fi
    else
        echo "  ❌ Password authentication failed - skipping host"
        ((failed_hosts++))
    fi
done

echo ""
echo "=========================================="
echo "SSH Key Deployment Summary:"
echo "  Successful: $successful_hosts hosts"
echo "  Failed: $failed_hosts hosts" 
echo "  Total: ${#HOSTS[@]} hosts"
echo "=========================================="

if [ $successful_hosts -gt 0 ]; then
    echo ""
    echo "You can now trigger host monitoring to update their status from 'reachable' to 'online'."
fi