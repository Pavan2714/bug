import os
import json
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from config import Config

def verify_google_token(token):
    """
    Verify Google ID token and return user info
    """
    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            token, 
            google_requests.Request(), 
            Config.GOOGLE_CLIENT_ID
        )
        
        # ID token is valid. Get the user's Google Account ID and profile info
        google_id = idinfo['sub']
        email = idinfo['email']
        name = idinfo.get('name', email.split('@')[0])
        picture = idinfo.get('picture')
        
        return {
            'google_id': google_id,
            'email': email,
            'name': name,
            'picture': picture
        }
    except ValueError as e:
        # Invalid token
        print(f"Invalid token: {e}")
        return None
    except Exception as e:
        print(f"Error verifying token: {e}")
        return None

def get_google_user_info(access_token):
    """
    Get user info from Google using access token
    """
    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers=headers)
        
        if response.status_code == 200:
            user_info = response.json()
            return {
                'google_id': user_info['id'],
                'email': user_info['email'],
                'name': user_info.get('name', user_info['email'].split('@')[0]),
                'picture': user_info.get('picture')
            }
        else:
            print(f"Error getting user info: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error getting user info: {e}")
        return None 