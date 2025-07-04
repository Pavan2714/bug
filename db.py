# Database utility functions

import sqlite3
import bcrypt
import os
from config import Config
import secrets
from datetime import datetime, timedelta

DB_PATH = Config.DB_PATH
from flask_login import UserMixin

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, profile_image=None, google_id=None, auth_provider='local'):
        self.id = id
        self.username = username
        self.email = email
        self.profile_image = profile_image
        self.google_id = google_id
        self.auth_provider = auth_provider
    
    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, profile_image, google_id, auth_provider FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if not user:
                return None
            
            return User(user['id'], user['username'], user['email'], user['profile_image'], user['google_id'], user['auth_provider'])
        except sqlite3.Error as err:
            print(f"Error getting user: {err}")
            return None
        finally:
            conn.close()

    @staticmethod
    def get_by_google_id(google_id):
        conn = get_db_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, profile_image, google_id, auth_provider FROM users WHERE google_id = ?", (google_id,))
            user = cursor.fetchone()
            if not user:
                return None
            
            return User(user['id'], user['username'], user['email'], user['profile_image'], user['google_id'], user['auth_provider'])
        except sqlite3.Error as err:
            print(f"Error getting user by Google ID: {err}")
            return None
        finally:
            conn.close()

    @staticmethod
    def get_by_email(email):
        conn = get_db_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, profile_image, google_id, auth_provider FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            if not user:
                return None
            
            return User(user['id'], user['username'], user['email'], user['profile_image'], user['google_id'], user['auth_provider'])
        except sqlite3.Error as err:
            print(f"Error getting user by email: {err}")
            return None
        finally:
            conn.close()

# Create a connection to the SQLite database
def get_db_connection():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        return conn
    except sqlite3.Error as err:
        print(f"Error connecting to SQLite database: {err}")
        return None

# User authentication functions
def register_user(username, email, password):
    """Register a new user"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error"
    
    try:
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            return False, "Username or email already exists"
        
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insert the new user
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_password.decode('utf-8'))
        )
        conn.commit()
        return True, "User registered successfully"
    except sqlite3.Error as err:
        print(f"Error: {err}")
        return False, str(err)


def login_user(username, password):
    """Authenticate a user"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error", None
    
    try:
        cursor = conn.cursor()
        
        # Get user by username
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            return False, "Invalid username or password", None
        
        # Convert SQLite Row to dict for consistency
        user_dict = dict(user)
        
        # Check password
        if bcrypt.checkpw(password.encode('utf-8'), user_dict['password'].encode('utf-8')):
            # Create a User object for Flask-Login
            user_obj = User(user_dict['id'], user_dict['username'], user_dict['email'], user_dict.get('profile_image'), user_dict.get('google_id'), user_dict.get('auth_provider'))
            return True, "Login successful", user_obj
        else:
            return False, "Invalid username or password", None
    except sqlite3.Error as err:
        print(f"Error: {err}")
        return False, str(err), None
    finally:
        conn.close()

# Admin authentication functions
def login_admin(username, password):
    """Authenticate an admin"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error", None
    
    try:
        cursor = conn.cursor()
        
        # Get admin by username
        cursor.execute("SELECT * FROM admins WHERE username = ?", (username,))
        admin = cursor.fetchone()
        
        if not admin:
            return False, "Invalid username or password", None
        
        # Convert SQLite Row to dict for consistency
        admin_dict = dict(admin)
        
        # Check password
        if bcrypt.checkpw(password.encode('utf-8'), admin_dict['password'].encode('utf-8')):
            # Remove password from admin data before returning
            admin_dict.pop('password', None)
            return True, "Login successful", admin_dict
        else:
            return False, "Invalid username or password", None
    except sqlite3.Error as err:
        print(f"Error: {err}")
        return False, str(err), None
    finally:
        conn.close()

# Function to get all users
def get_all_users():
    """Fetch all users from the database"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, profile_image, created_at FROM users ORDER BY created_at DESC")
        users = [dict(user) for user in cursor.fetchall()]
        return users
    except sqlite3.Error as err:
        print(f"Error fetching users: {err}")
        return []
    finally:
        conn.close()

# Function to update user's profile image
def update_profile_image(user_id, image_path):
    """Update user's profile image in the database"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error"
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET profile_image = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (image_path, user_id)
        )
        conn.commit()
        
        if cursor.rowcount > 0:
            return True, "Profile image updated successfully"
        else:
            return False, "User not found"
    except sqlite3.Error as err:
        print(f"Error updating profile image: {err}")
        return False, str(err)
    finally:
        conn.close()

# Google OAuth functions
def create_google_user(google_id, email, username, profile_image=None):
    """Create a new user with Google OAuth"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error", None
    
    try:
        cursor = conn.cursor()
        
        # Check if user already exists with this Google ID
        cursor.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
        if cursor.fetchone():
            return False, "User already exists with this Google account", None
        
        # Check if email already exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            return False, "Email already registered", None
        
        # Check if username already exists and generate a unique one if needed
        original_username = username
        counter = 1
        while True:
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                break  # Username is unique
            username = f"{original_username}_{counter}"
            counter += 1
        
        # Insert the new Google user
        cursor.execute(
            "INSERT INTO users (username, email, google_id, auth_provider, profile_image) VALUES (?, ?, ?, ?, ?)",
            (username, email, google_id, 'google', profile_image)
        )
        conn.commit()
        
        # Get the created user
        user_id = cursor.lastrowid
        user = User(user_id, username, email, profile_image, google_id, 'google')
        return True, "Google user created successfully", user
    except sqlite3.Error as err:
        print(f"Error creating Google user: {err}")
        return False, str(err), None
    finally:
        conn.close()

def get_or_create_google_user(google_id, email, username, profile_image=None):
    """Get existing Google user or create new one"""
    # First try to get existing user by Google ID
    user = User.get_by_google_id(google_id)
    if user:
        # Update profile image if provided and different
        if profile_image and user.profile_image != profile_image:
            update_profile_image(user.id, profile_image)
            user.profile_image = profile_image
        return True, "User found", user
    
    # If not found, create new user
    return create_google_user(google_id, email, username, profile_image)

def update_profile_image_for_google_user(user_id, new_profile_image):
    """Update profile image for Google users (can be URL or local file)"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error"
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET profile_image = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (new_profile_image, user_id)
        )
        conn.commit()
        
        if cursor.rowcount > 0:
            return True, "Profile image updated successfully"
        else:
            return False, "User not found"
    except sqlite3.Error as err:
        print(f"Error updating profile image: {err}")
        return False, str(err)
    finally:
        conn.close()

# Initialize database
def init_db():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error"
    
    try:
        cursor = conn.cursor()
        
        # Create users table if not exists
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT,
            profile_image TEXT,
            google_id TEXT UNIQUE,
            auth_provider TEXT DEFAULT 'local',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Check if new columns exist in users table
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        column_names = [column['name'] for column in columns]
        
        # Add new columns if they don't exist
        if 'profile_image' not in column_names:
            cursor.execute("ALTER TABLE users ADD COLUMN profile_image TEXT")
            print("Added profile_image column to users table")
        
        if 'google_id' not in column_names:
            # Create a temporary table to handle the UNIQUE constraint
            cursor.execute("""
            CREATE TABLE users_temp (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT,
                profile_image TEXT,
                google_id TEXT UNIQUE,
                auth_provider TEXT DEFAULT 'local',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            
            # Copy data from old table to new table
            cursor.execute("""
            INSERT INTO users_temp (id, username, email, password, profile_image, created_at, updated_at)
            SELECT id, username, email, password, profile_image, created_at, updated_at FROM users
            """)
            
            # Drop old table and rename new table
            cursor.execute("DROP TABLE users")
            cursor.execute("ALTER TABLE users_temp RENAME TO users")
            print("Added google_id column to users table")
        
        if 'auth_provider' not in column_names:
            cursor.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'local'")
            print("Added auth_provider column to users table")
        
        # Update existing users to have 'local' auth_provider
        cursor.execute("UPDATE users SET auth_provider = 'local' WHERE auth_provider IS NULL")
        
        conn.commit()
        
        # Create admins table if not exists
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Create images table if not exists
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            processed_filename TEXT NOT NULL,
            detection_results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """)
        
        # Create password reset tokens table if not exists
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """)
        
        # Check if default admin exists
        cursor.execute("SELECT * FROM admins WHERE username = 'admin'")
        if not cursor.fetchone():
            # Create default admin user
            hashed_password = bcrypt.hashpw(b'admin123', bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO admins (username, email, password) VALUES (?, ?, ?)",
                ('admin', 'admin@example.com', hashed_password.decode('utf-8'))
            )
        
        conn.commit()
        return True, "Database initialized successfully"
    except sqlite3.Error as err:
        print(f"Error initializing database: {err}")
        return False, str(err)
    finally:
        conn.close()

# Function to add image metadata
def add_image(user_id, original_filename, processed_filename, detection_results):
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error"
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO images (user_id, original_filename, processed_filename, detection_results) VALUES (?, ?, ?, ?)',
            (user_id, original_filename, processed_filename, detection_results)
        )
        conn.commit()
        return True, "Image added successfully"
    except sqlite3.Error as err:
        print(f"Error adding image: {err})")
        return False, str(err)
    finally:
         conn.close()

def get_user_images(user_id):
    conn = get_db_connection()
    if not conn:
        return []
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM images WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        images = [dict(row) for row in cursor.fetchall()]
        return images
    except sqlite3.Error as err:
        print(f"Error fetching user images: {err}")
        return []
    finally:
        conn.close()

def get_user_videos(user_id):
    # This function is a placeholder as video processing is not yet implemented.
    # It should fetch video metadata from a 'videos' table similar to get_user_images.
    return []

# Password reset functionality
def create_password_reset_token(email):
    """Create a password reset token for the given email"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error", None
    
    try:
        cursor = conn.cursor()
        
        # Check if user exists with this email
        cursor.execute("SELECT id, username FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if not user:
            return False, "No user found with this email address", None
        
        # Generate a secure token
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=1)  # Token expires in 1 hour
        
        # Store the token in the database
        cursor.execute(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user['id'], token, expires_at)
        )
        conn.commit()
        
        return True, "Password reset token created", {
            'user_id': user['id'],
            'username': user['username'],
            'email': email,
            'token': token
        }
    except sqlite3.Error as err:
        print(f"Error creating password reset token: {err}")
        return False, str(err), None
    finally:
        conn.close()

def verify_password_reset_token(token):
    """Verify a password reset token and return user info if valid"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error", None
    
    try:
        cursor = conn.cursor()
        
        # Check if token exists and is not expired
        cursor.execute(
            "SELECT prt.user_id, prt.expires_at, u.username, u.email FROM password_reset_tokens prt JOIN users u ON prt.user_id = u.id WHERE prt.token = ? AND prt.expires_at > ?",
            (token, datetime.now())
        )
        result = cursor.fetchone()
        
        if not result:
            return False, "Invalid or expired token", None
        
        return True, "Token is valid", {
            'user_id': result['user_id'],
            'username': result['username'],
            'email': result['email']
        }
    except sqlite3.Error as err:
        print(f"Error verifying password reset token: {err}")
        return False, str(err), None
    finally:
        conn.close()

def update_user_password(user_id, new_password):
    """Update user's password"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error"
    
    try:
        cursor = conn.cursor()
        
        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update the password
        cursor.execute(
            "UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (hashed_password.decode('utf-8'), user_id)
        )
        
        # Delete all password reset tokens for this user
        cursor.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
        
        conn.commit()
        return True, "Password updated successfully"
    except sqlite3.Error as err:
        print(f"Error updating password: {err}")
        return False, str(err)
    finally:
        conn.close()

def cleanup_expired_tokens():
    """Clean up expired password reset tokens"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection error"
    
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM password_reset_tokens WHERE expires_at <= ?", (datetime.now(),))
        conn.commit()
        return True, "Expired tokens cleaned up"
    except sqlite3.Error as err:
        print(f"Error cleaning up expired tokens: {err}")
        return False, str(err)
    finally:
        conn.close()