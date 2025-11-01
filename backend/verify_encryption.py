#!/usr/bin/env python3
"""
Quick verification script for refactored encryption module.

This script tests the new encryption module without requiring pytest.
Run this before committing to verify everything works.
"""
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.encryption import (
    EncryptionService,
    create_encryption_service,
    EncryptionConfig,
    KDFAlgorithm,
    FAST_TEST_CONFIG,
    HIGH_SECURITY_CONFIG,
    EncryptionError,
    DecryptionError,
    InvalidDataError,
    ConfigurationError
)


def test_basic_encryption():
    """Test basic encrypt/decrypt"""
    print("Testing basic encryption/decryption...")
    service = EncryptionService("test-key", FAST_TEST_CONFIG)

    plaintext = b"Hello, World!"
    encrypted = service.encrypt(plaintext)
    decrypted = service.decrypt(encrypted)

    assert decrypted == plaintext, "Decrypted data doesn't match!"
    print("✓ Basic encryption/decryption works")


def test_unicode():
    """Test unicode string encryption"""
    print("Testing unicode encryption...")
    service = EncryptionService("test-key", FAST_TEST_CONFIG)

    plaintext = "Hello 世界 🌍".encode('utf-8')
    encrypted = service.encrypt(plaintext)
    decrypted = service.decrypt(encrypted)

    assert decrypted.decode('utf-8') == "Hello 世界 🌍"
    print("✓ Unicode encryption works")


def test_different_configs():
    """Test different encryption configs"""
    print("Testing different configs...")

    # Fast config
    service1 = EncryptionService("key", FAST_TEST_CONFIG)
    assert service1.config.kdf_iterations == 10000

    # High security config
    service2 = EncryptionService("key", HIGH_SECURITY_CONFIG)
    assert service2.config.kdf_iterations == 200000
    assert service2.config.kdf_algorithm == KDFAlgorithm.SHA512

    print("✓ Different configs work")


def test_no_singleton():
    """Test that multiple instances are independent"""
    print("Testing no singleton pattern...")

    service1 = create_encryption_service("key1", FAST_TEST_CONFIG)
    service2 = create_encryption_service("key2", FAST_TEST_CONFIG)

    # Should be different objects
    assert service1 is not service2
    assert service1.master_key != service2.master_key

    print("✓ No singleton - instances are independent")


def test_invalid_data():
    """Test that invalid data raises InvalidDataError"""
    print("Testing invalid data handling...")

    service = EncryptionService("key", FAST_TEST_CONFIG)

    try:
        service.decrypt(b"too short")
        assert False, "Should have raised InvalidDataError"
    except InvalidDataError as e:
        assert "too short" in str(e)
        print("✓ Invalid data raises InvalidDataError")


def test_wrong_key():
    """Test that wrong key raises DecryptionError"""
    print("Testing wrong key handling...")

    service1 = EncryptionService("key1", FAST_TEST_CONFIG)
    service2 = EncryptionService("key2", FAST_TEST_CONFIG)

    encrypted = service1.encrypt(b"secret")

    try:
        service2.decrypt(encrypted)
        assert False, "Should have raised DecryptionError"
    except DecryptionError as e:
        assert "Decryption failed" in str(e)
        print("✓ Wrong key raises DecryptionError")


def test_config_validation():
    """Test config validation"""
    print("Testing config validation...")

    # Too few iterations
    try:
        EncryptionConfig(kdf_iterations=5000)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "10000" in str(e)
        print("✓ Config validation rejects too few iterations")

    # Invalid key length
    try:
        EncryptionConfig(key_length=20)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "16" in str(e) and "32" in str(e)
        print("✓ Config validation rejects invalid key length")


def test_exception_hierarchy():
    """Test exception inheritance"""
    print("Testing exception hierarchy...")

    # DecryptionError is EncryptionError
    assert issubclass(DecryptionError, EncryptionError)
    assert issubclass(InvalidDataError, EncryptionError)
    assert issubclass(ConfigurationError, EncryptionError)

    # All inherit from Exception
    assert issubclass(EncryptionError, Exception)

    print("✓ Exception hierarchy correct")


def test_authenticated_encryption():
    """Test that GCM provides authentication (tamper detection)"""
    print("Testing authenticated encryption...")

    service = EncryptionService("key", FAST_TEST_CONFIG)
    encrypted = service.encrypt(b"secret data")

    # Tamper with ciphertext
    tampered = bytearray(encrypted)
    tampered[30] ^= 0xFF
    tampered_bytes = bytes(tampered)

    try:
        service.decrypt(tampered_bytes)
        assert False, "Should have detected tampering"
    except DecryptionError:
        print("✓ Tampering detected (authenticated encryption works)")


def main():
    """Run all tests"""
    print("=" * 60)
    print("Encryption Module Verification")
    print("=" * 60)
    print()

    tests = [
        test_basic_encryption,
        test_unicode,
        test_different_configs,
        test_no_singleton,
        test_invalid_data,
        test_wrong_key,
        test_config_validation,
        test_exception_hierarchy,
        test_authenticated_encryption,
    ]

    failed = []

    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            failed.append(test.__name__)

    print()
    print("=" * 60)
    if failed:
        print(f"❌ {len(failed)} test(s) FAILED:")
        for name in failed:
            print(f"   - {name}")
        print("=" * 60)
        sys.exit(1)
    else:
        print("✅ All tests PASSED!")
        print("=" * 60)
        sys.exit(0)


if __name__ == "__main__":
    main()
