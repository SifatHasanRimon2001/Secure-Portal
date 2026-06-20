# Secure Portal 🔐

A modern, full-featured secure web portal with end-to-end encryption, password hashing, and comprehensive security features.

## Features ✨

### Security
- **End-to-End Encryption**: All user data encrypted with AES-256 using Fernet (symmetric encryption)
- **Password Hashing**: Passwords secured with scrypt hashing and salting
- **Per-User Keys**: Each user has a unique encryption key encrypted with the master key
- **MAC Integrity Check**: All encrypted data verified with HMAC-SHA256
- **Session Protection**: Strong session protection with HTTPOnly cookies
- **Audit Logging**: Complete audit trail of all system activities (encrypted)
- **Lookup Encryption**: Username lookups use HMAC to prevent enumeration attacks

### Features
- User Registration with strong password requirements
- User Login with session persistence
- User Profile & Credentials Management
- Create & View Encrypted Posts
- Admin Dashboard
  - User Management (view and delete users)
  - Audit Logs (view all system activities)
- Modern, responsive UI with glassmorphism design
- Dark theme with beautiful gradient backgrounds

## Tech Stack

- **Backend**: Flask 3.0.3
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Flask-Login with custom UserMixin
- **Encryption**: cryptography (Fernet)
- **Forms**: Flask-WTF with WTForms validation
- **Frontend**: Bootstrap 5.3.3 with custom CSS
- **Security**: Werkzeug for password hashing

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

1. **Create Virtual Environment**
   ```bash
   python -m venv .venv
   source .venv/Scripts/activate  # On Windows
   # or
   source .venv/bin/activate      # On Linux/Mac
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment**
   - Copy `.env.example` to `.env` and set your own values
   - `SECRET_KEY`: Flask session secret (use a strong random value)
   - `ADMIN_USERNAME`: Your admin username
   - `ADMIN_PASSWORD`: Your admin password (must meet password requirements)
   - `DATABASE_URL`: SQLite database path

4. **Run the Application**
   ```bash
   python run.py
   ```

5. **Access the Portal**
   - Open your browser and navigate to: `http://localhost:5000`
   - Create your admin account on first run or use the credentials set in `.env`

## How to Use

### 1. Register New Account
- Click "Register" on the login page
- Enter username (3-30 characters)
- Enter display name
- Create a strong password (min 8 chars, uppercase, lowercase, number, special char)
- Confirm password
- Click "Create Account"

### 2. Login
- Enter your username
- Enter your password
- Click "Login"

### 3. Create Encrypted Posts
- On the Dashboard, enter your message in the post area
- Click "Encrypt & Save"
- Your post is now encrypted with your unique key

### 4. View Your Posts
- All your posts are displayed on the right side of the dashboard
- Posts are automatically decrypted with your unique key
- Posts show with integrity verification status

### 5. Verify Credentials
- Go to "Credentials" page
- Enter your password to verify your identity
- Your account information is displayed (username, display name, role, creation date)

### 6. Admin Panel (Admin Only)
- Go to "Admin" page
- View all users in the system
- Delete users (except yourself)
- Each action is logged in the audit trail

### 7. Audit Logs (Admin Only)
- Go to "Audit Logs" page
- View all system activities
- See who logged in, created posts, etc.
- All logs are encrypted and integrity-checked

## Encryption Architecture

### Master Key Management
- Master encryption key stored in `instance/keys/encryption.key`
- HMAC key stored in `instance/keys/hmac.key`
- Username lookup key stored in `instance/keys/lookup.key`
- All keys are 32-byte random values

### Data Encryption Flow
1. **User Registration**:
   - Generate unique per-user key
   - Encrypt all user info with master key
   - Generate MAC for integrity
   - Encrypt per-user key with master key

2. **Post Encryption**:
   - Encrypt post content with user's unique key
   - Generate MAC for post
   - Store encrypted post and MAC

3. **Data Decryption**:
   - Verify MAC for integrity
   - Decrypt user key with master key
   - Decrypt data with user key
   - Return plaintext

## Database Schema

### Users Table
- `id`: Primary key
- `username_lookup`: HMAC of normalized username (for secure lookups)
- `username_enc`: Encrypted username
- `display_name_enc`: Encrypted display name
- `role_enc`: Encrypted role (ADMIN/USER)
- `created_at_enc`: Encrypted creation timestamp
- `user_key_enc`: Encrypted per-user encryption key
- `user_mac`: MAC for integrity verification
- `password_hash`: Scrypt-hashed password

### Posts Table
- `id`: Primary key
- `user_id`: Foreign key to users
- `ciphertext`: Encrypted post content
- `mac`: MAC for integrity verification

### Audit Logs Table
- `id`: Primary key
- `action_enc`: Encrypted action (LOGIN, LOGOUT, etc.)
- `actor_enc`: Encrypted actor username
- `target_enc`: Encrypted target (username, post ID, etc.)
- `timestamp_enc`: Encrypted timestamp
- `mac`: MAC for integrity verification

## Security Best Practices Implemented

✓ All passwords hashed with scrypt (not reversible)
✓ All user data encrypted at rest
✓ All posts encrypted with per-user keys
✓ Integrity checks on all encrypted data via MAC
✓ Session cookies marked as HTTPOnly and SameSite
✓ Strong password requirements (uppercase, lowercase, numbers, special chars)
✓ Audit trail of all user actions
✓ Secure logout clears session
✓ Admin-only pages protected with decorators
✓ CSRF protection on all forms
✓ Username lookups use HMAC to prevent enumeration

## File Structure

```
secure_portal/
├── app/
│   ├── __init__.py           # Flask app factory
│   ├── models.py             # Database models
│   ├── routes.py             # Route handlers
│   ├── services.py           # Business logic
│   ├── crypto.py             # Encryption/decryption
│   ├── decorators.py         # Custom decorators
│   ├── forms.py              # WTForms forms
│   │
│   ├── templates/
│   │   ├── base.html         # Base template with navbar
│   │   ├── login.html        # Login page
│   │   ├── register.html     # Registration page
│   │   ├── dashboard.html    # Main dashboard
│   │   ├── credentials.html  # Credential verification
│   │   ├── admin.html        # Admin panel
│   │   └── audit_logs.html   # Audit logs viewer
│   │
│   └── static/
│       └── css/
│           └── style.css     # Main stylesheet
│
├── instance/
│   ├── secure_portal.db      # SQLite database
│   └── keys/
│       ├── encryption.key    # Master encryption key
│       ├── hmac.key          # HMAC key
│       └── lookup.key        # Lookup encryption key
│
├── run.py                    # Application entry point
├── requirements.txt          # Python dependencies
└── .env                      # Environment configuration
```

## Environment Variables

```
SECRET_KEY              # Flask session secret key
ADMIN_USERNAME          # Default admin username
ADMIN_PASSWORD          # Default admin password
ADMIN_DISPLAY_NAME      # Default admin display name
DATABASE_URL            # Database connection string
```

## API Endpoints

### Authentication
- `GET /login` - Login page
- `POST /login` - Process login
- `GET /register` - Registration page
- `POST /register` - Process registration
- `GET /logout` - Logout (requires authentication)

### User
- `GET /dashboard` - Main dashboard
- `POST /dashboard` - Create encrypted post
- `GET /credentials` - Credential verification page
- `POST /credentials` - Verify credentials

### Admin (requires admin role)
- `GET /admin` - Admin panel with user list
- `POST /admin/delete/<user_id>` - Delete user
- `GET /audit-logs` - View audit logs

## Password Requirements

Passwords must contain:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (!@#$%^&*, etc.)

Example: `SecurePass123!`

## Troubleshooting

### Database Issues
- Delete `instance/secure_portal.db` and restart to recreate
- Keys in `instance/keys/` will be regenerated automatically

### Encryption Errors
- Ensure `instance/keys/` directory exists and is writable
- Check that all key files have correct permissions

### Login Issues
- Ensure admin account is created (check app startup logs)
- Check that `.env` contains valid `ADMIN_USERNAME` and `ADMIN_PASSWORD`

### Missing Dependencies
- Run `pip install -r requirements.txt` again
- Ensure virtual environment is activated

## Development Notes

### Adding New Users
- Use the registration page (no manual SQL needed)
- All user data is automatically encrypted

### Adding New Posts
- Dashboard form automatically handles encryption
- MAC verification happens on display

### Admin Functions
- Only users with role "ADMIN" can access admin pages
- Deleting a user also deletes all their posts (cascade)
- All admin actions are logged in audit trail

## Security Warnings

⚠️ **DEVELOPMENT ONLY**: This app uses Flask's development server. For production:
- Use a WSGI server (Gunicorn, uWSGI, etc.)
- Set `debug=False`
- Use a strong random SECRET_KEY
- Use PostgreSQL or other production database
- Enable HTTPS/SSL
- Store keys in a proper key management system (not in instance/keys/)
- Implement rate limiting and account lockout
- Add CAPTCHA to registration/login

## License

This project is provided as-is for educational purposes.

## Support

For issues or questions, check the code comments for detailed explanations of the encryption/security implementation.
