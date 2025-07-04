#!/usr/bin/env python3
"""
Email Test Script for YOLO Object Detection
This script tests the email configuration to ensure Gmail SMTP is working correctly.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import email_config

def test_email_configuration():
    """Test the email configuration"""
    print("Testing Email Configuration...")
    print(f"SMTP Server: {email_config.SMTP_SERVER}")
    print(f"SMTP Port: {email_config.SMTP_PORT}")
    print(f"Email Username: {email_config.EMAIL_USERNAME}")
    print(f"From Email: {email_config.FROM_EMAIL}")
    print(f"App Password: {'*' * len(email_config.EMAIL_PASSWORD)} (hidden)")
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = email_config.FROM_EMAIL
        msg['To'] = email_config.EMAIL_USERNAME  # Send to yourself for testing
        msg['Subject'] = 'Test Email - YOLO Object Detection'
        
        body = """This is a test email from the YOLO Object Detection application.

If you receive this email, the email configuration is working correctly.

Best regards,
YOLO Object Detection Team"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to SMTP server
        print("\nConnecting to SMTP server...")
        server = smtplib.SMTP(email_config.SMTP_SERVER, email_config.SMTP_PORT)
        server.starttls()
        
        print("Authenticating...")
        server.login(email_config.EMAIL_USERNAME, email_config.EMAIL_PASSWORD)
        
        print("Sending test email...")
        server.send_message(msg)
        server.quit()
        
        print("✅ Test email sent successfully!")
        print(f"Check your inbox at {email_config.EMAIL_USERNAME}")
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        print("\nPossible solutions:")
        print("1. Make sure 2-factor authentication is enabled on your Gmail account")
        print("2. Generate a new App Password: https://myaccount.google.com/apppasswords")
        print("3. Use the App Password (16 characters) instead of your regular password")
        print("4. Make sure 'Less secure app access' is not enabled (it's deprecated)")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\nCheck your internet connection and Gmail settings.")

if __name__ == "__main__":
    test_email_configuration() 