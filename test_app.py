#!/usr/bin/env python
"""
Quick start test script for Secure Portal
Tests all major functionality
"""
import sys

from app import create_app, db, init_database
from app.models import User, SecurePost, AuditLog
from app.services import (
    register_user,
    verify_credentials,
    encrypt_post_for_user,
    decrypt_post_for_user,
    get_username,
    get_display_name,
    get_user_role,
    get_all_users,
    get_audit_logs
)


def test_registration():
    """Test user registration"""
    print("Testing User Registration...")
    user = register_user('testuser1', 'Test User 1', 'TestPass123!')
    assert user is not None, "User registration failed"
    assert user.id > 0, "User ID not set"
    print("✓ User registration working\n")
    return user


def test_login(user, password):
    """Test login credentials"""
    print("Testing Login/Credentials...")
    result = verify_credentials(user, password)
    assert result, "Credential verification failed"
    print("✓ Login credentials working\n")


def test_encryption(user):
    """Test post encryption/decryption"""
    print("Testing Encryption/Decryption...")

    # Encrypt a post
    test_content = "This is a secret message! 🔐"
    ciphertext, mac = encrypt_post_for_user(user, test_content)
    assert ciphertext != test_content, "Content not encrypted"
    assert mac, "MAC not generated"
    print(f"  ✓ Post encrypted successfully")

    # Create post in database
    from datetime import datetime
    from app.services import get_next_post_serial_number
    post = SecurePost(
        user_id=user.id,
        serial_number=get_next_post_serial_number(user),
        created_at=datetime.utcnow(),
        ciphertext=ciphertext,
        mac=mac,
    )
    db.session.add(post)
    db.session.commit()
    print(f"  ✓ Post stored in database")

    # Decrypt the post
    decrypted = decrypt_post_for_user(user, post)
    assert decrypted == test_content, "Decryption failed"
    print(f"  ✓ Post decrypted successfully")
    print("✓ Encryption/Decryption working\n")


def test_user_info(user):
    """Test user info retrieval"""
    print("Testing User Info Retrieval...")
    username = get_username(user)
    display_name = get_display_name(user)
    role = get_user_role(user)
    assert username, "Username not retrieved"
    assert display_name, "Display name not retrieved"
    assert role, "Role not retrieved"
    print(f"  Username: {username}")
    print(f"  Display Name: {display_name}")
    print(f"  Role: {role}")
    print("✓ User info retrieval working\n")


def test_admin_functions():
    """Test admin functions"""
    print("Testing Admin Functions...")
    # Get all users
    all_users = get_all_users()
    assert isinstance(all_users, list), "Failed to get users list"
    print(f"  ✓ Retrieved {len(all_users)} users")

    # Get audit logs
    logs = get_audit_logs()
    assert isinstance(logs, list), "Failed to get audit logs"
    print(f"  ✓ Retrieved {len(logs)} audit log entries")
    print("✓ Admin functions working\n")


def main():
    """Run all tests"""
    print("\n" + "=" * 50)
    print("SECURE PORTAL - QUICK START TEST")
    print("=" * 50 + "\n")

    try:
        # Initialise database (creates tables and admin user)
        init_database()
        print("✓ Database initialised\n")

        # Run tests
        user = test_registration()
        test_login(user, 'TestPass123!')
        test_encryption(user)
        test_user_info(user)
        test_admin_functions()

        print("=" * 50)
        print("ALL TESTS PASSED! ✓")
        print("=" * 50)
        print("\nYou can now run the app with: python run.py")
        print("Then open: http://localhost:5000")
        print("\nAdmin Credentials (from .env):")
        print("  Username: Check ADMIN_USERNAME in .env")
        print("  Password: Check ADMIN_PASSWORD in .env\n")

    except Exception as e:
        print(f"\n✗ TEST FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
