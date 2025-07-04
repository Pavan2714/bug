# Forgot Password Functionality

This document describes the forgot password functionality implemented in the YOLO Object Detection application.

## Features

### 1. Forgot Password Request

- Users can request a password reset by entering their email address
- The system validates the email and creates a secure reset token
- A password reset link is sent to the user's email (currently logged to console for development)

### 2. Password Reset

- Users receive a secure, time-limited reset link (1 hour expiration)
- The reset page allows users to enter a new password
- Password confirmation validation ensures passwords match
- Minimum password length requirement (6 characters)

### 3. Security Features

- Secure token generation using `secrets.token_urlsafe(32)`
- Time-limited tokens (1 hour expiration)
- Tokens are automatically cleaned up after use
- No information disclosure about email existence
- Password hashing using bcrypt

### 4. Responsive Design

- Fully responsive design that works on all device sizes
- Mobile-optimized interface
- Consistent styling with the main application

## Database Schema

### Password Reset Tokens Table

```sql
CREATE TABLE password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## Routes

### 1. `/forgot-password` (GET/POST)

- **GET**: Display forgot password form
- **POST**: Process password reset request
- **Access**: Public (no authentication required)

### 2. `/reset-password/<token>` (GET/POST)

- **GET**: Display password reset form (if token is valid)
- **POST**: Process password reset
- **Access**: Public (no authentication required)

## Email Configuration

### Development Mode

- Password reset links are logged to the console
- No actual emails are sent
- Check the console output for reset links

### Production Mode

To enable actual email sending:

1. Update `email_config.py` with your SMTP settings
2. Uncomment the SMTP code in `send_password_reset_email()` function
3. Configure your email credentials

### Gmail Setup Example

```python
# In email_config.py
EMAIL_USERNAME = 'your-email@gmail.com'
EMAIL_PASSWORD = 'your-app-password'  # Use App Password, not regular password
```

## Usage Flow

1. **User clicks "Forgot Password?"** on login page
2. **User enters email address** on forgot password page
3. **System validates email** and creates reset token
4. **Reset link is sent** to user's email (logged to console in development)
5. **User clicks reset link** in email
6. **User enters new password** on reset page
7. **Password is updated** and user can log in

## Security Considerations

- Tokens expire after 1 hour
- Tokens are single-use (deleted after password reset)
- No information disclosure about email existence
- Secure token generation
- Password confirmation validation
- Minimum password requirements

## Testing

### Test the Forgot Password Flow:

1. Go to the login page
2. Click "Forgot Password?"
3. Enter an existing email address
4. Check the console for the reset link
5. Click the reset link
6. Enter a new password
7. Try logging in with the new password

### Test Security Features:

1. Try resetting password with non-existent email
2. Try using an expired token
3. Try using an invalid token
4. Try submitting mismatched passwords

## Files Modified/Created

### New Files:

- `templates/forgot_password.html` - Forgot password form
- `templates/reset_password.html` - Password reset form
- `email_config.py` - Email configuration
- `FORGOT_PASSWORD_README.md` - This documentation

### Modified Files:

- `webapp.py` - Added password reset routes and email functionality
- `db.py` - Added password reset database functions
- `templates/login_new.html` - Added forgot password link
- `static/css/auth_new.css` - Added responsive styles for password reset

## Future Enhancements

1. **Email Templates**: Create HTML email templates
2. **Rate Limiting**: Implement rate limiting for password reset requests
3. **Audit Logging**: Log password reset attempts
4. **Multiple Email Providers**: Support for different email services
5. **SMS Reset**: Add SMS-based password reset option
