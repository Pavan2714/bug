import argparse
import os
import io
from PIL import Image
import datetime
import torch
import cv2
import numpy as np
import tensorflow as tf
from re import DEBUG, sub
from flask import Flask, render_template, request, redirect, send_file, url_for, Response, session, flash,jsonify, make_response
from werkzeug.utils import secure_filename, send_from_directory
import os
import subprocess
from subprocess import Popen
import re
import requests
import shutil
import time
import glob
import logging
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import email_config

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
import json
from ultralytics import YOLO
import functools
import threading
import queue
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
import config
from db import get_db_connection, register_user, User, get_all_users, update_profile_image, add_image, get_user_images, get_user_videos, init_db, login_user as login_user_db, login_admin, get_or_create_google_user, update_profile_image_for_google_user, create_password_reset_token, verify_password_reset_token, update_user_password
from google_oauth import verify_google_token, get_google_user_info
from threading import Lock

# Add at the top with other globals
frame_lock = Lock()


# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config.from_object(config.Config)

webcam = None
webcam_active = False

# Load YOLO model globally
model = YOLO('best.pt')

# List of routes that do not require authentication
public_routes = [
    'login_new',
    'signup_new',
    'landing',
    'static',
    'admin_login_new',
    'admin_login',
    'register',
    'login',
    'index', # index redirects to landing if not authenticated
    'google_login',
    'google_callback',
    'google_signup',
    'forgot_password',
    'reset_password'
]

@app.before_request
def check_authentication():
    # Check if user is authenticated for protected routes
    # Allow access to public routes without authentication
    app.logger.debug(f"check_authentication: Endpoint: {request.endpoint}, Session keys: {list(session.keys())}, Is authenticated: {current_user.is_authenticated}")

    if request.endpoint in public_routes:
        app.logger.debug(f"check_authentication: Public route, returning.")
        return

    # If an admin is logged in, allow access to admin routes
    if 'admin_id' in session and request.endpoint.startswith('admin_'):
        app.logger.debug(f"check_authentication: Admin session found for admin route, returning.")
        return

    # Check if user is authenticated for protected user routes
    if not current_user.is_authenticated:
        return redirect(url_for('login_new'))
    
    # Additional security check for authenticated user routes
    # Verify session is valid and not expired
    if 'user_id' not in session:
        logout_user()
        return redirect(url_for('login_new'))
    
    # Check if user_id in session matches current_user.id
    if str(current_user.id) != str(session.get('user_id')):
        logout_user()
        return redirect(url_for('login_new'))

@app.after_request
def add_security_headers(response):
    # Set strong cache control headers to prevent caching of sensitive pages
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    # Add security headers to prevent clickjacking and other attacks
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

# Helper function to get user-specific upload folder
def get_user_upload_folder(user_id):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{user_id}')
    os.makedirs(user_folder, exist_ok=True)
    return user_folder

# Helper function to get user-specific result folder
def get_user_result_folder(user_id):
    user_folder = os.path.join(app.config['RESULT_FOLDER'], f'user_{user_id}')
    os.makedirs(user_folder, exist_ok=True)
    return user_folder

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_new'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from db import User
    return User.get(user_id)

# Queue for video processing
video_queue = queue.Queue(maxsize=5)  # Limit queue size
video_result = None
video_processing = False

# Initialize database and ensure directories exist when app starts
with app.app_context():
    # Ensure directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

    success, message = init_db()
    if not success:
        print(f"Database initialization failed: {message}")

# We're now using Flask-Login's @login_required decorator instead of this custom middleware

# Admin authentication middleware
def admin_required(view_func):
    @functools.wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return view_func(*args, **kwargs)
    return wrapped_view

# Routes for authentication
@app.route('/login-new', methods=['GET', 'POST'])
def login_new():
    if current_user.is_authenticated:
        app.logger.info(f"User already authenticated, redirecting to dashboard. User: {current_user.username}")
        return redirect(url_for('dashboard'))
    error = None
    success = request.args.get('success')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        app.logger.info(f"Login attempt for username: {username}")
        success_login, message, user = login_user_db(username, password)
        
        if success_login:
            # Use Flask-Login's login_user function
            session['user_id'] = user.id
            session['user_username'] = user.username
            login_user(user)
            app.logger.info(f"Login successful for user: {username}, redirecting to dashboard")
            return redirect(url_for('dashboard'))
        else:
            error = message
            app.logger.warning(f"Login failed for {username}: {message}")
    
    return render_template('login_new.html', error=error, success=success)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Redirect to the new signup page
    return redirect(url_for('signup_new'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect to the new login page
    return redirect(url_for('login_new'))

@app.route('/signup-new', methods=['GET', 'POST'])
def signup_new():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    error = None
    success = None
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            error = "Passwords do not match"
        else:
            success_register, message = register_user(username, email, password)
            
            if success_register:
                success = message
                # Redirect to login page after successful registration
                return redirect(url_for('login_new', success=message))
            else:
                error = message
    
    return render_template('signup_new.html', error=error, success=success)

@app.route('/logout')
def logout():
    # Use Flask-Login's logout_user function
    logout_user()
    
    # Clear all session data
    session.clear()
    
    # Create response with redirect
    response = redirect(url_for('login_new'))
    
    # Set cache control headers to prevent back button access
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    return response

# Password reset routes
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle forgot password requests"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    error = None
    success = None
    
    if request.method == 'POST':
        email = request.form['email']
        
        # Create password reset token
        success_reset, message, user_data = create_password_reset_token(email)
        
        if success_reset:
            # Send password reset email
            try:
                send_password_reset_email(user_data['email'], user_data['username'], user_data['token'])
                success = "Password reset instructions have been sent to your email address."
            except Exception as e:
                app.logger.error(f"Error sending password reset email: {e}")
                error = "Failed to send password reset email. Please try again."
        else:
            # Don't reveal if email exists or not for security
            success = "If an account with that email exists, password reset instructions have been sent."
    
    return render_template('forgot_password.html', error=error, success=success)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handle password reset with token"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    error = None
    success = None
    
    # Verify token
    valid_token, message, user_data = verify_password_reset_token(token)
    
    if not valid_token:
        error = "Invalid or expired password reset link. Please request a new one."
        return render_template('reset_password.html', error=error, token=token)
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            error = "Passwords do not match"
        elif len(password) < 6:
            error = "Password must be at least 6 characters long"
        else:
            # Update password
            success_update, message = update_user_password(user_data['user_id'], password)
            
            if success_update:
                success = "Password has been reset successfully. You can now log in with your new password."
            else:
                error = message
    
    return render_template('reset_password.html', error=error, success=success, token=token, user_data=user_data)

def send_password_reset_email(email, username, token):
    """Send password reset email"""
    reset_url = url_for('reset_password', token=token, _external=True)
    
    app.logger.info(f"Password reset link for {username} ({email}): {reset_url}")
    
    try:
        msg = MIMEMultipart()
        msg['From'] = email_config.FROM_EMAIL
        msg['To'] = email
        msg['Subject'] = email_config.PASSWORD_RESET_SUBJECT
        
        body = email_config.get_password_reset_body(username, reset_url)
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Configure SMTP settings
        server = smtplib.SMTP(email_config.SMTP_SERVER, email_config.SMTP_PORT)
        server.starttls()
        server.login(email_config.EMAIL_USERNAME, email_config.EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        app.logger.info(f"Password reset email sent successfully to {email}")
        
    except Exception as e:
        app.logger.error(f"Error sending email: {e}")
        # For development, still log the reset link even if email fails
        print(f"Password reset link for {username} ({email}): {reset_url}")
        raise

# Google OAuth routes
@app.route('/google-login')
def google_login():
    """Initiate Google OAuth login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    # For now, we'll use a simple approach with Google Sign-In button
    # In a production app, you'd redirect to Google's OAuth URL
    return redirect(url_for('login_new'))

@app.route('/google-callback', methods=['POST'])
def google_callback():
    """Handle Google OAuth callback with ID token"""
    if current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'Already authenticated'})
    
    try:
        data = request.get_json()
        if not data or 'credential' not in data:
            return jsonify({'success': False, 'message': 'No credential provided'}), 400
        
        # Verify the Google ID token
        user_info = verify_google_token(data['credential'])
        if not user_info:
            return jsonify({'success': False, 'message': 'Invalid Google token'}), 400
        
        # Get or create user
        success, message, user = get_or_create_google_user(
            user_info['google_id'],
            user_info['email'],
            user_info['name'],
            user_info['picture']
        )
        
        if success:
            # Login the user
            session['user_id'] = user.id
            session['user_username'] = user.username
            login_user(user)
            
            return jsonify({
                'success': True,
                'message': 'Google login successful'
            })
        else:
            return jsonify({'success': False, 'message': message}), 400
            
    except Exception as e:
        app.logger.error(f"Google callback error: {e}")
        return jsonify({'success': False, 'message': 'Authentication failed'}), 500

@app.route('/google-signup', methods=['POST'])
def google_signup():
    """Handle Google OAuth signup"""
    if current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'Already authenticated'})
    
    try:
        data = request.get_json()
        if not data or 'credential' not in data:
            return jsonify({'success': False, 'message': 'No credential provided'}), 400
        
        # Verify the Google ID token
        user_info = verify_google_token(data['credential'])
        if not user_info:
            return jsonify({'success': False, 'message': 'Invalid Google token'}), 400
        
        # Create new Google user
        success, message, user = get_or_create_google_user(
            user_info['google_id'],
            user_info['email'],
            user_info['name'],
            user_info['picture']
        )
        
        if success:
            # Login the user
            session['user_id'] = user.id
            session['user_username'] = user.username
            login_user(user)
            
            return jsonify({
                'success': True,
                'message': 'Google signup successful'
            })
        else:
            return jsonify({'success': False, 'message': message}), 400
            
    except Exception as e:
        app.logger.error(f"Google signup error: {e}")
        return jsonify({'success': False, 'message': 'Signup failed'}), 500

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # Redirect to the new admin login page
    return redirect(url_for('admin_login_new'))

@app.route('/admin/login-new', methods=['GET', 'POST'])
def admin_login_new():
    error = None
    success = None
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        success_login, message, admin = login_admin(username, password)
        
        if success_login:
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            app.logger.info(f"Admin login successful for {username}. Session admin_id: {session.get('admin_id')}")
            return redirect(url_for('admin_dashboard'))
        else:
            error = message
    
    return render_template('admin_login_new.html', error=error, success=success)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Placeholder data - in a real app, you would fetch this from the database
    admin = {'username': session.get('admin_username', 'Admin')}
    user_count = 10
    image_count = 25
    video_count = 5
    
    activities = [
        {
            'icon': 'fas fa-user-plus',
            'text': 'New user registered',
            'time': '2 hours ago'
        },
        {
            'icon': 'fas fa-image',
            'text': 'Image processed by user john_doe',
            'time': '3 hours ago'
        },
        {
            'icon': 'fas fa-video',
            'text': 'Video processed by user jane_smith',
            'time': '5 hours ago'
        }
    ]
    
    current_year = datetime.now().year
    
    return render_template('admin_dashboard.html', 
                           admin=admin, 
                           user_count=user_count, 
                           image_count=image_count, 
                           video_count=video_count, 
                           activities=activities,
                           current_year=current_year)

@app.route('/admin/users')
@admin_required
def admin_users():
    # Get all users from the database
    from db import get_all_users
    users = get_all_users()
    
    # Get current year for footer
    current_year = datetime.now().year
    
    return render_template('admin_users.html', users=users, current_year=current_year)

@app.route('/admin/settings')
@admin_required
def admin_settings():
    # This would be implemented to manage system settings
    return "Admin Settings Page"

@app.route('/admin/logout')
def admin_logout():
    # Clear admin session data
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    
    # Clear all session data for extra security
    session.clear()
    
    # Create response with redirect
    response = redirect(url_for('admin_login'))
    
    # Set cache control headers to prevent back button access
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    return response

# Main application routes
@app.route("/")
@login_required
def index():
    # Redirect to dashboard page
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = current_user.id
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    os.makedirs(user_folder, exist_ok=True)

    # Fetch user-specific images and videos from the database
    user_images = get_user_images(user_id)
    user_videos = get_user_videos(user_id)

    # Check if webcam is available (assuming it's always available for now)
    webcam_available = True

    return render_template('dashboard.html', user_images=user_images, user_videos=user_videos, webcam_available=webcam_available, webcam_active=webcam_active)


@app.route('/processing')
@login_required
def processing():
    return render_template('processing.html')



@app.route('/upload_and_process', methods=['POST'])
@login_required
def upload_and_process():
    if 'file' not in request.files:
        app.logger.error('No image part in the request')
        return jsonify({'success': False, 'message': 'No image part in the request'}), 400
    file = request.files['file']
    if file.filename == '':
        app.logger.error('No selected image')
        return jsonify({'success': False, 'message': 'No selected image'}), 400
    if file:
        filename = secure_filename(file.filename)
        user_id = current_user.id
        user_upload_folder = get_user_upload_folder(user_id)
        os.makedirs(user_upload_folder, exist_ok=True)
        filepath = os.path.join(user_upload_folder, filename)
        file.save(filepath)
        app.logger.info(f"User ID: {user_id}")
        app.logger.info(f"Upload folder: {user_upload_folder}")
        app.logger.info(f"Filename: {filename}")
        app.logger.info(f"Saved file to: {filepath}")
        app.logger.info(f"File exists after save: {os.path.exists(filepath)}")

        try:
            # Prepare response data
            response_data = {
                'success': True,
                'filename': filename,
                'upload_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'file_size': os.path.getsize(filepath),
                'user_id': user_id
            }
            
            file_extension = filename.rsplit('.', 1)[1].lower()
            app.logger.debug(f"File extension: {file_extension}")
            
            # Process based on file type
            if file_extension in ['jpg', 'jpeg', 'png', 'gif']:
                app.logger.debug(f"Calling detect_objects for image file: {filepath}")
                processed_file_path, detection_info = detect_objects(filepath, user_id, model)
                response_data['file_type'] = 'image'
            elif file_extension in ['mp4', 'avi', 'mov', 'mkv']:
                app.logger.debug(f"Calling process_video for video file: {filepath}")
                processed_file_path, detection_info = process_video(filepath, user_id, model)
                response_data['file_type'] = 'video'
            else:
                app.logger.warning(f"Unsupported file type: {file_extension} for file {filename}")
                return jsonify({'success': False, 'message': 'Unsupported file type'}), 400

            # Store detection results in the database
            from db import add_image
            db_result = add_image(user_id, filename, processed_file_path, json.dumps(detection_info))
            app.logger.info(f"add_image DB result: {db_result}")

            # For url_for('static', filename=...), we need the path relative to the 'static' folder.
            if processed_file_path.startswith('static/'):
                relative_static_path = processed_file_path[len('static/'):]
            else:
                relative_static_path = os.path.basename(processed_file_path)

            processed_file_url = url_for('static', filename=relative_static_path)
            response_data['processed_file_url'] = processed_file_url
            response_data['results'] = detection_info

            object_types = {}
            for result in detection_info:
                if '%' in result:
                    object_type = result.split(' (')[0]
                    if object_type in object_types:
                        object_types[object_type] += 1
                    else:
                        object_types[object_type] = 1
            response_data['object_summary'] = object_types
            response_data['total_objects'] = sum(object_types.values()) if object_types else 0
            response_data['processing_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            return jsonify(response_data)
        except Exception as e:
            app.logger.error(f"Error during object detection: {e}")
            error_response = {
                'success': False,
                'message': f'Error during detection: {str(e)}',
                'error_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'filename': filename,
                'error_details': str(e)
            }
            return jsonify(error_response), 500



def detect_objects(image_path, user_id, model):
    app.logger.debug(f"Inside detect_objects. Attempting to read image from: {image_path}")
    # model = YOLO('best.pt') # Model will be passed as an argument or loaded globally  # Load your YOLO model
    if not os.path.exists(image_path):
        app.logger.error(f"Image file not found: {image_path}")
        raise Exception(f"Image file not found: {image_path}")
    
    # Detailed processing steps
    detection_info = []
    
    # Step 1: Load the image
    img = cv2.imread(image_path)
    if img is None:
        app.logger.error(f"Failed to read image file: {image_path}. cv2.imread returned None. Check file corruption or permissions.")
        raise Exception("Could not read image file for detection. It might be corrupted or permissions are incorrect.")
    
    # Get image dimensions for logging
    height, width, channels = img.shape
    detection_info.append(f"Image loaded: {width}x{height} pixels, {channels} channels")
    
    # Step 2: Run the YOLO model
    detection_info.append("Running YOLO object detection model...")
    results = model(img)
    detection_info.append("Detection complete!")
    
    # Step 3: Save the processed image
    user_result_folder = get_user_result_folder(user_id)
    processed_filename = "detected_" + os.path.basename(image_path)
    processed_image_path = os.path.join(user_result_folder, processed_filename)
    detection_info.append(f"Saving processed image to {processed_filename}")
    
    # Render results on the image
    res_plotted = results[0].plot()
    cv2.imwrite(processed_image_path, res_plotted)
    detection_info.append("Processed image saved successfully")
    
    # Step 4: Extract detection results (e.g., class names and confidence)
    detection_info.append("Detected objects:")
    object_count = 0
    for r in results:
        for box in r.boxes:
            object_count += 1
            class_id = int(box.cls[0])
            class_name = model.names[class_id]
            confidence = float(box.conf[0])
            detection_info.append(f"{class_name} ({(confidence*100):.2f}%)")
    
    if object_count == 0:
        detection_info.append("No objects detected in the image")
    else:
        detection_info.append(f"Total objects detected: {object_count}")
    
    return processed_image_path, detection_info

def process_video(video_path, user_id, model):
    app.logger.debug(f"Inside process_video. Attempting to open video from: {video_path}")
    # model = YOLO('best.pt') # Model is passed as an argument
    if not os.path.exists(video_path):
        app.logger.error(f"Video file not found: {video_path}")
        raise Exception(f"Video file not found: {video_path}")
    
    # Detailed processing steps
    detection_info = []
    detection_info.append("Starting video processing...")
    
    # Step 1: Open the video file
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        app.logger.error(f"Failed to open video file: {video_path}. cv2.VideoCapture returned False. Check file corruption or codecs.")
        raise Exception("Could not open video file. It might be corrupted or required codecs are missing.")
    
    # Step 2: Get video properties
    frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = int(cap.get(cv2.CAP_PROP_FPS))
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration = total_frames / fps if fps > 0 else 0
    
    detection_info.append(f"Video loaded: {frame_width}x{frame_height} pixels, {fps} FPS")
    detection_info.append(f"Total frames: {total_frames}, Duration: {duration:.2f} seconds")
    
    # Step 3: Prepare output video file
    user_result_folder = get_user_result_folder(user_id)
    output_filename = "detected_" + os.path.basename(video_path)
    output_path = os.path.join(user_result_folder, output_filename)
    detection_info.append(f"Output will be saved to: {output_filename}")
    
    fourcc = cv2.VideoWriter_fourcc(*'mp4v') # Codec for .mp4 files
    out = cv2.VideoWriter(output_path, fourcc, fps, (frame_width, frame_height))
    
    # Step 4: Process each frame
    detection_info.append("Processing video frames...")
    frame_count = 0
    object_counts = {}
    
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        
        frame_count += 1
        if frame_count % 10 == 0 or frame_count == 1:
            # Update status every 10 frames or on first frame
            detection_info.append(f"Processing frame {frame_count}/{total_frames} ({(frame_count/total_frames*100):.1f}%)")
        
        results = model(frame, save=False)
        res_plotted = results[0].plot()
        
        # Track objects in this frame
        frame_objects = []
        for r in results:
            for box in r.boxes:
                class_id = int(box.cls[0])
                class_name = model.names[class_id]
                confidence = float(box.conf[0])
                
                # Count objects by class
                if class_name not in object_counts:
                    object_counts[class_name] = 0
                object_counts[class_name] += 1
                
                # Only add unique detections to the info list
                label = f"{class_name} ({(confidence*100):.2f}%)"
                if label not in frame_objects:
                    frame_objects.append(label)
        
        # Add unique detections from this frame
        for obj in frame_objects:
            if obj not in detection_info:
                detection_info.append(obj)
        
        out.write(res_plotted)
    
    # Step 5: Finalize video processing
    cap.release()
    out.release()
    
    # Add summary information
    detection_info.append(f"Video processing complete! Processed {frame_count} frames.")
    detection_info.append("Object detection summary:")
    
    if not object_counts:
        detection_info.append("No objects detected in the video")
    else:
        for class_name, count in object_counts.items():
            detection_info.append(f"{class_name}: {count} instances")
        detection_info.append(f"Total objects detected: {sum(object_counts.values())}")
    
    return output_path, detection_info






@app.route("/uploads")
@login_required
def uploads():
    user_uploads = []
    images = get_user_images(current_user.id)
    uploads_dir = get_user_upload_folder(current_user.id)
    for img in images:
        file_path = os.path.join(uploads_dir, img['original_filename'])
        if os.path.exists(file_path):  # Only show if file exists
            user_uploads.append({
                'filename': img['original_filename'],
                'path': os.path.join('uploads', f'user_{current_user.id}', img['original_filename']),
                'date': img['created_at'][:16]
            })
    return render_template('uploads.html', user_uploads=user_uploads)

@app.route("/results")
@login_required
def results():
    # Get user's detection results
    user_results = []
    
    # Get user-specific result folder
    results_dir = get_user_result_folder(current_user.id)
    if os.path.exists(results_dir):
        for filename in os.listdir(results_dir):
            if filename.lower().endswith(('.jpg', '.jpeg', '.mp4')):
                user_results.append({
                    'filename': filename,
                    'path': os.path.join('results', f'user_{current_user.id}', filename),
                    'date': datetime.fromtimestamp(os.path.getmtime(os.path.join(results_dir, filename))).strftime('%Y-%m-%d %H:%M')
                })
    
    return render_template('results.html', user_results=user_results)

@app.route("/landing")
def landing():
    current_year = datetime.now().year
    return render_template('landing.html', current_year=current_year)

@app.route("/detect", methods=["GET", "POST"])
@login_required  # Using Flask-Login's login_required
def predict_img():
    if request.method == "POST":
        if 'file' in request.files:
            f = request.files['file']
            # Get user-specific upload folder
            user_upload_folder = get_user_upload_folder(current_user.id)
            
            # Save file to user's upload folder
            filename = secure_filename(f.filename)
            filepath = os.path.join(user_upload_folder, filename)
            print("upload folder is", filepath)
            f.save(filepath)
            
            global imgpath
            predict_img.imgpath = filename
            print("Printing Predicted img :::::", predict_img)

            file_extension = f.filename.rsplit('.', 1)[1].lower()

            if file_extension == 'jpg':
                try:
                    # Read the image
                    img = cv2.imread(filepath)
                    if img is None:
                        flash("Error: Could not read the image file.")
                        return redirect(url_for('uploads'))
                        
                    frame = cv2.imencode('.jpg', cv2.UMat(img))[1].tobytes()
                    image = Image.open(io.BytesIO(frame))

                    # Perform the detection
                    yolo = YOLO('best.pt')
                    
                    # Save the detection result directly to the user's result folder
                    result_filename = filename
                    user_result_folder = get_user_result_folder(current_user.id)
                    result_save_path = os.path.join(user_result_folder, result_filename)
                    
                    # Process the image and save directly to user's folder
                    results = yolo(image)
                    res_plotted = results[0].plot()
                    
                    # Convert from BGR to RGB for PIL
                    res_plotted_rgb = cv2.cvtColor(res_plotted, cv2.COLOR_BGR2RGB)
                    result_image = Image.fromarray(res_plotted_rgb)
                    result_image.save(result_save_path)
                    
                    print(f"Detection result saved to: {result_save_path}")
                    
                    # Redirect to results page
                    return redirect(url_for('results'))
                    
                except Exception as e:
                    # Log the error and flash a message to the user
                    print(f"Error processing image: {str(e)}")
                    flash(f"Error processing image: {str(e)}")
                    return redirect(url_for('uploads'))
            
            elif file_extension == 'mp4':
                try:
                    # Create a unique output filename based on user ID and timestamp
                    output_filename = f"output_{current_user.id}_{int(time.time())}.mp4"
                    output_path = os.path.join(os.path.dirname(__file__), output_filename)
                    
                    video_path = filepath
                    cap = cv2.VideoCapture(video_path)
                    
                    if not cap.isOpened():
                        flash("Error: Could not open video file.")
                        return redirect(url_for('uploads'))

                    # Get video dimensions
                    frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                    frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

                    # Define codec and create videowriter object
                    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
                    out = cv2.VideoWriter(output_path, fourcc, 30.0, (frame_width, frame_height))

                    # Initialize YOLOv8 model
                    model = YOLO('best.pt')
                    
                    # Process video frames
                    frame_count = 0
                    while cap.isOpened():
                        ret, frame = cap.read()
                        if not ret:
                            break

                        # Perform YOLOv8 detection on the frame
                        results = model(frame, save=False)  # Don't save individual frames
                        
                        # Plot results on frame
                        res_plotted = results[0].plot()
                        
                        # Write the frame to the output video
                        out.write(res_plotted)
                        
                        frame_count += 1
                        if frame_count % 10 == 0:  # Log progress every 10 frames
                            print(f"Processed {frame_count} frames")
                    
                    # Close resources
                    cap.release()
                    out.release()
                    
                    # Copy the output video to the user's results folder
                    result_filename = filename
                    user_result_folder = get_user_result_folder(current_user.id)
                    result_save_path = os.path.join(user_result_folder, result_filename)
                    shutil.copy(output_path, result_save_path)
                    
                    # Clean up the temporary output file
                    if os.path.exists(output_path):
                        os.remove(output_path)
                
                    # Redirect to results page
                    return redirect(url_for('results'))
                except Exception as e:
                    # Log the error and flash a message to the user
                    print(f"Error processing video: {str(e)}")
                    flash(f"Error processing video: {str(e)}")
                    return redirect(url_for('uploads'))
            else:
                # Unsupported file extension
                flash(f"Unsupported file extension: {file_extension}. Please upload a jpg, jpeg, or mp4 file.")
                return redirect(url_for('uploads'))
    
    # If we get here, something went wrong (no file uploaded or POST request)
    flash("No file selected or invalid request.")
    return redirect(url_for('uploads'))



def get_frame(video_path=None):
    # If no specific video path is provided, look for the most recent video in the user's result folder
    if video_path is None or not os.path.exists(video_path):
        # Ensure current_user is available and authenticated
        if current_user and current_user.is_authenticated:
            user_result_folder = get_user_result_folder(current_user.id)
            # Look for mp4 files in the user's result folder
            mp4_files = [f for f in os.listdir(user_result_folder) if f.lower().endswith('.mp4')]
            
            if mp4_files:
                # Sort by modification time (newest first)
                mp4_files.sort(key=lambda x: os.path.getmtime(os.path.join(user_result_folder, x)), reverse=True)
                video_path = os.path.join(user_result_folder, mp4_files[0])
            else:
                video_path = None
        else:
            video_path = None
    
    # If no valid video path is found, return an error message
    if video_path is None or not os.path.exists(video_path):
        # Create a blank image with error message
        blank_image = np.zeros((480, 640, 3), np.uint8)
        cv2.putText(blank_image, 'No processed video available', (50, 240), 
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
        ret, jpeg = cv2.imencode('.jpg', blank_image)
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + jpeg.tobytes() + b'\r\n\r\n')
        return
    
    # Open the video file
    video = cv2.VideoCapture(video_path)
    
    # If video can't be opened, use a placeholder or error message
    if not video.isOpened():
        # Create a blank image with error message
        blank_image = np.zeros((480, 640, 3), np.uint8)
        cv2.putText(blank_image, 'Video not available', (50, 240), 
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
        ret, jpeg = cv2.imencode('.jpg', blank_image)
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + jpeg.tobytes() + b'\r\n\r\n')
        return
    
    # Read and yield frames from the video
    while True:
        success, image = video.read()
        if not success:
            # If end of video, loop back to beginning
            video.set(cv2.CAP_PROP_POS_FRAMES, 0)
            continue
            
        ret, jpeg = cv2.imencode('.jpg', image)
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + jpeg.tobytes() + b'\r\n\r\n')
        time.sleep(0.1)  # control the frame rate to display one frame every 100 milliseconds

# function to display the detected objects video on html page
@app.route("/video_feed")
@login_required  # Using Flask-Login's login_required
def video_feed():
    print("Video Feed Function Called")
    # Get the most recent video from the user's result folder
    if current_user.is_authenticated:
        user_result_folder = get_user_result_folder(current_user.id)
        # Look for mp4 files in the user's result folder
        mp4_files = [f for f in os.listdir(user_result_folder) if f.lower().endswith('.mp4')]
        
        if mp4_files:
            # Sort by modification time (newest first)
            mp4_files.sort(key=lambda x: os.path.getmtime(os.path.join(user_result_folder, x)), reverse=True)
            video_path = os.path.join(user_result_folder, mp4_files[0])
            return Response(get_frame(video_path), mimetype='multipart/x-mixed-replace; boundary=frame')
    
    # If no video is found or user is not authenticated, return error frames
    return Response(get_frame(None), mimetype='multipart/x-mixed-replace; boundary=frame')
    
    # Error handling is now done in the get_frame function

# Global variables for webcam and detection
webcam = None
webcam_active = False
live_detection_active = False
detection_results = []
detection_stats = {
    'object_count': 0,
    'fps': 0,
    'detection_time': 0
}

# Route for webcam feed detection
@app.route('/webcam_feed')
@login_required
def webcam_feed():
    """Video streaming route for webcam with object detection."""
    return Response(generate_webcam_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# Route for live detection feed
@app.route('/live_feed')
@login_required
def live_feed():
    """Video streaming route for live detection."""
    return Response(generate_live_detection_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# Function to start webcam
@app.route('/start_webcam')
@login_required
def start_webcam():
    global webcam, webcam_active
    
    # Try multiple camera indices if 0 fails
    for camera_index in [0, 1, 2]:
        webcam = cv2.VideoCapture(camera_index)
        if webcam.isOpened():
            time.sleep(0.5) # Give camera a moment to warm up
            break
            
    if not webcam.isOpened():
        return jsonify({
            'success': False,
            'message': 'Could not open any webcam. Please check camera connection.'
        })
    
    webcam_active = True
    return jsonify({'success': True, 'message': 'Webcam started'})

# Function to stop webcam
@app.route('/stop_webcam')
@login_required
def stop_webcam():
    global webcam, webcam_active
    if webcam is not None and webcam.isOpened():
        webcam_active = False
        webcam.release()
        time.sleep(0.5) # Give camera a moment to release resources
        webcam = None
    return redirect(url_for('index'))

# Function to generate webcam frames with YOLO detection
def generate_webcam_frames():
    global webcam, webcam_active
    
    # Initialize YOLO model
    model = YOLO('best.pt')
    
    while webcam_active:
        success, frame = webcam.read()
        if not success:
            break
        else:
            # Perform detection on the frame
            results = model(frame)
            
            # Draw detection results on the frame
            annotated_frame = results[0].plot()
            
            # Convert to JPEG
            ret, buffer = cv2.imencode('.jpg', annotated_frame)
            frame_bytes = buffer.tobytes()
            
            # Yield the frame in the response
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
            
            # Control frame rate
            time.sleep(0.04)  # ~25 FPS

# Live Detection Page
@app.route('/live_detection')
@login_required
def live_detection():
    return render_template('live_detection.html')

# Start live detection
@app.route('/start_live_detection')
@login_required
def start_live_detection():
    global webcam, live_detection_active, detection_results, detection_stats, latest_annotated_frame
    
    # Reset detection results and stats
    detection_results = []
    detection_stats = {
        'object_count': 0,
        'fps': 0,
        'detection_time': 0
    }
    
    # Initialize webcam if not already open
    if webcam is None or not webcam.isOpened():
        webcam = cv2.VideoCapture(0)  # 0 is usually the default webcam
        if not webcam.isOpened():
            logging.error("Could not open webcam. Please check your camera connection.")
            return jsonify({
                'success': False,
                'message': 'Could not open webcam. Please check your camera connection.'
            })
        else:
            logging.info("Webcam opened successfully.")
    
    # Initialize latest_annotated_frame with a blank frame
    success, frame = webcam.read()
    if success:
        logging.debug("Webcam successfully opened and frame read for initialization.")
        # Create a blank frame with a message
        latest_annotated_frame = frame.copy()
        cv2.putText(latest_annotated_frame, 'Starting detection...', (50, 240), 
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
    else:
        logging.warning("Failed to read initial frame from webcam for initialization.")
    
    live_detection_active = True
    
    # Start the live detection processing in a separate thread
    detection_thread = threading.Thread(target=process_live_detection)
    detection_thread.daemon = True
    detection_thread.start()
    logging.debug("Live detection thread started.")
    

    
    return jsonify({
        'success': True,
        'message': 'Live detection started successfully.'
    })



# Stop live detection
@app.route('/stop_live_detection')
@login_required
def stop_live_detection():
    global live_detection_active, webcam
    
    live_detection_active = False
    if webcam is not None:
        webcam.release()
        webcam = None
    
    return jsonify({
        'success': True,
        'message': 'Live detection stopped successfully.'
    })

# Capture current frame
@app.route('/capture_frame')
@login_required
def capture_frame():
    global webcam, detection_results
    
    if webcam is None or not webcam.isOpened():
        return jsonify({
            'success': False,
            'message': 'Webcam is not active.'
        })
    
    # Capture frame
    success, frame = webcam.read()
    if not success:
        return jsonify({
            'success': False,
            'message': 'Failed to capture frame from webcam.'
        })
    
    # Generate a unique filename
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'capture_{current_user.id}_{timestamp}.jpg'
    
    # Save to a temporary location
    temp_folder = os.path.join(app.static_folder, 'temp')
    os.makedirs(temp_folder, exist_ok=True)
    temp_path = os.path.join(temp_folder, filename)
    
    # Save the frame
    cv2.imwrite(temp_path, frame)
    
    # Return the image URL and metadata
    return jsonify({
        'success': True,
        'image_url': url_for('static', filename=f'temp/{filename}'),
        'image_path': temp_path,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'object_count': len(detection_results)
    })

# Save captured frame to user's results
@app.route('/save_captured_frame', methods=['POST'])
@login_required
def save_captured_frame():
    data = request.json
    image_path = data.get('image_path')
    
    if not image_path or not os.path.exists(image_path):
        return jsonify({
            'success': False,
            'message': 'Invalid image path or image not found.'
        })
    
    try:
        # Get user's result folder
        user_result_folder = get_user_result_folder(current_user.id)
        
        # Generate a filename for the saved image
        filename = f'live_capture_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.jpg'
        save_path = os.path.join(user_result_folder, filename)
        
        # Copy the image to the user's result folder
        shutil.copy(image_path, save_path)
        
        return jsonify({
            'success': True,
            'message': 'Frame saved successfully.',
            'saved_path': save_path
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error saving frame: {str(e)}'
        })

# Global variable to store the latest annotated frame
latest_annotated_frame = None
frame_lock = threading.Lock()

# Function to process live detection in a separate thread
def process_live_detection():
    global webcam, live_detection_active, detection_results, detection_stats, latest_annotated_frame
    
    try:
        model = YOLO('best.pt')
        fps_counter = 0
        start_time = time.time()
        
        while live_detection_active:
            if webcam is None or not webcam.isOpened():
                time.sleep(0.1)
                logging.debug("process_live_detection: Webcam not active or not opened.")
                continue
                
            # Capture frame
            ret, frame = webcam.read()
            if not ret:
                logging.warning("process_live_detection: Failed to read frame from webcam.")
                continue
            logging.debug("process_live_detection: Frame captured.")
                
            # Perform detection
            det_start = time.time()
            results = model(frame)
            det_time = (time.time() - det_start) * 1000  # ms
            
            # Process results
            current_results = []
            for r in results[0].boxes.data.tolist():
                x1, y1, x2, y2, conf, cls = r
                current_results.append({
                    'class': model.names[int(cls)],
                    'confidence': float(conf),
                    'bbox': [float(x1), float(y1), float(x2), float(y2)]
                })
            
            # Update stats
            fps_counter += 1
            if (time.time() - start_time) >= 1.0:
                fps = fps_counter / (time.time() - start_time)
                fps_counter = 0
                start_time = time.time()
                
            with frame_lock:
                detection_stats['object_count'] = len(current_results)
                detection_stats['fps'] = fps if 'fps' in locals() else 0
                detection_stats['detection_time'] = det_time
                detection_results = current_results
                latest_annotated_frame = results[0].plot()
                logging.debug(f"process_live_detection: Updated latest_annotated_frame, objects: {len(current_results)}, FPS: {detection_stats['fps']:.2f}")
            
            time.sleep(0.01)  # Prevent CPU overload
    except Exception as e:
        logging.error(f"Error in process_live_detection thread: {e}", exc_info=True)
    finally:
        logging.info("process_live_detection thread finished.")

# Function to generate live detection frames for streaming
def generate_live_detection_frames():
    global latest_annotated_frame, live_detection_active
    
    while True:
        if not live_detection_active or webcam is None or not webcam.isOpened():
            blank_frame = np.zeros((480, 640, 3), np.uint8)
            message = 'Click Start Detection to begin' if not live_detection_active else 'Webcam not available'
            cv2.putText(blank_frame, message, (50, 240), 
                        cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
            ret, buffer = cv2.imencode('.jpg', blank_frame)
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            time.sleep(0.5)
            continue
        
        with frame_lock:
            if latest_annotated_frame is not None:
                frame = latest_annotated_frame.copy()
            else:
                # If no frame has been annotated yet, create a blank one
                frame = np.zeros((480, 640, 3), np.uint8)
                cv2.putText(frame, 'Waiting for detection...', (50, 240), 
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)

        
        ret, buffer = cv2.imencode('.jpg', frame)
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
        time.sleep(0.04)  # ~25 FPS

# Get detection results
@app.route('/get_detection_results')
@login_required
def get_detection_results():
    global detection_results, detection_stats
    
    return jsonify({
        'success': True,
        'results': detection_results,
        'object_count': detection_stats['object_count'],
        'fps': detection_stats['fps'],
        'detection_time': detection_stats['detection_time']
    })





# Route for handling profile image uploads
@app.route('/upload_profile_image', methods=['POST'])
@login_required
def upload_profile_image():
    if 'profile_image' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'}), 400
    
    file = request.files['profile_image']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400
    
    if file and allowed_file(file.filename, {'jpg', 'jpeg', 'png'}):
        # Create a unique filename based on user ID
        filename = f"profile_{current_user.id}.{file.filename.rsplit('.', 1)[1].lower()}"
        
        # Get user-specific upload folder
        user_upload_folder = get_user_upload_folder(current_user.id)
        
        # Save the file
        file_path = os.path.join(user_upload_folder, filename)
        file.save(file_path)
        
        # Update the user's profile image in the database
        relative_path = f"uploads/user_{current_user.id}/{filename}"
        
        # Use the appropriate update function based on user type
        if current_user.auth_provider == 'google':
            success, message = update_profile_image_for_google_user(current_user.id, relative_path)
        else:
            success, message = update_profile_image(current_user.id, relative_path)
        
        if success:
            # Update the current_user object with the new profile image path
            current_user.profile_image = relative_path
            print(f"DEBUG: current_user.profile_image after update: {current_user.profile_image}")
            
            return jsonify({
                'success': True, 
                'message': 'Profile image updated successfully',
                'profile_image_url': url_for('static', filename=relative_path)
            })
        else:
            return jsonify({'success': False, 'message': f'Database error: {message}'}), 500
    
    return jsonify({'success': False, 'message': 'Invalid file type'}), 400

# Routes for deleting uploads and results
@app.route('/delete_upload/<path:file_path>', methods=['POST'])
@login_required
def delete_upload(file_path):
    try:
        # Ensure the file path is within the user's specific upload folder
        user_upload_folder = get_user_upload_folder(current_user.id)
        filename = os.path.basename(file_path)
        expected_prefix = os.path.join('uploads', f'user_{current_user.id}')
        if not file_path.startswith(expected_prefix):
            return jsonify({'success': False, 'message': 'Unauthorized file access attempt (path mismatch)'}), 403

        absolute_file_path = os.path.join(user_upload_folder, filename)

        # Remove from database
        from db import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM images WHERE user_id = ? AND original_filename = ?", (current_user.id, filename))
        conn.commit()
        conn.close()

        # Remove file if it exists
        if os.path.exists(absolute_file_path):
            os.remove(absolute_file_path)
            return jsonify({'success': True, 'message': 'File and DB record deleted successfully'})
        else:
            return jsonify({'success': True, 'message': 'DB record deleted, file not found (already deleted?)'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/delete_result/<path:file_path>', methods=['POST'])
@login_required
def delete_result(file_path):
    try:
        # Ensure the file path is within the user's specific result folder
        user_result_folder = get_user_result_folder(current_user.id)
        # Extract just the filename from the file_path provided in the URL
        filename = os.path.basename(file_path)

        # Validate that the file_path starts with the expected user-specific prefix
        expected_prefix = os.path.join('results', f'user_{current_user.id}')
        if not file_path.startswith(expected_prefix):
            return jsonify({'success': False, 'message': 'Unauthorized file access attempt (path mismatch)'}), 403

        absolute_file_path = os.path.join(user_result_folder, filename)


        
        # Check if file exists and belongs to the current user
        if os.path.exists(absolute_file_path):
            os.remove(absolute_file_path)
            return jsonify({'success': True, 'message': 'Result deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Result not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# Helper function to check if a file has an allowed extension
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/cleanup_uploads', methods=['POST'])
@login_required
def cleanup_uploads():
    # Get all files in the user's upload folder
    uploads_dir = get_user_upload_folder(current_user.id)
    all_files = set(os.listdir(uploads_dir)) if os.path.exists(uploads_dir) else set()

    # Get all files registered in the database
    db_files = set(img['original_filename'] for img in get_user_images(current_user.id))

    # Find files that are in the folder but not in the database
    orphan_files = all_files - db_files

    deleted = []
    for filename in orphan_files:
        file_path = os.path.join(uploads_dir, filename)
        try:
            os.remove(file_path)
            deleted.append(filename)
        except Exception as e:
            print(f"Error deleting {filename}: {e}")

    return jsonify({
        'success': True,
        'deleted_files': deleted,
        'message': f"Deleted {len(deleted)} orphan files."
    })

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Flask app exposing yolov8 models")
    parser.add_argument("--port", default=config.Config.PORT, type=int, help="port number")
    args = parser.parse_args()

    app.run(host='0.0.0.0', port=args.port, debug=True)










