#!/usr/bin/env python3
"""
Simple test script for the FastAPI server.
Replace the JWT token with a valid one from your Supabase setup.
"""

import requests
import json

# Configuration
BASE_URL = "http://localhost:8000"
JWT_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6IjFwdzlIM3h4UGpDZkc4cWgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3V4a3VjZnBhdnV1dWtjd3RheXduLnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJzdWIiOiI2OGY4YjFmNi05MzMyLTRiY2QtYjQyOC1mZWJiM2RmNDg3NjYiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiZXhwIjoxNzUzMTY1MzY2LCJpYXQiOjE3NTMxNjE3NjYsImVtYWlsIjoic2hyZXl4c0BnbWFpbC5jb20iLCJwaG9uZSI6IiIsImFwcF9tZXRhZGF0YSI6eyJwcm92aWRlciI6Imdvb2dsZSIsInByb3ZpZGVycyI6WyJnb29nbGUiXX0sInVzZXJfbWV0YWRhdGEiOnsiYXZhdGFyX3VybCI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0tjOUk2Ym9sNVNZWGRyRDNNVHVFOGtOZl9XVFdQOVU3SGE2dC12VFI2UnR0ejVnQk9lVXc9czk2LWMiLCJjaXR5IjoiRGVtYm9zIiwiY29tbWlzc2lvbiI6IjIlIiwiY29tcGFueSI6InN1cGVyY29tcCBkZmcgaW5jIiwiY291bnRyeSI6IkFuZ29sYSIsImRiYSI6Im5ldyBkYmEgMjMiLCJlbWFpbCI6InNocmV5eHNAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZ1bGxfbmFtZSI6IlNocmV5YXMgSmFta2hhbmRpIiwiZ2VvZ3JhcGh5Ijoic3VwZXIgZ2VvIiwiaGFzX3NoYXJlZF9wcmVmZXJlbmNlcyI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwibmFtZSI6IlNocmV5YXMgSmFta2hhbmRpIiwicGhvbmUiOiIrOTEgODY5ODUgOTMxNzgiLCJwaG9uZV92ZXJpZmllZCI6ZmFsc2UsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NLYzlJNmJvbDVTWVhkckQzTVR1RThrTmZfV1RXUDlVN0hhNnQtdlRSNlJ0dHo1Z0JPZVV3PXM5Ni1jIiwicHJvdmlkZXJfaWQiOiIxMTExMzYwMjkwNTcwNjk3NjcwMDciLCJyZXBfY29kZSI6IlJFUC0wMDMiLCJzdGF0ZSI6IkJlbmdvIiwic3ViIjoiMTExMTM2MDI5MDU3MDY5NzY3MDA3In0sInJvbGUiOiJhdXRoZW50aWNhdGVkIiwiYWFsIjoiYWFsMSIsImFtciI6W3sibWV0aG9kIjoib2F1dGgiLCJ0aW1lc3RhbXAiOjE3NDY4ODAyMDF9XSwic2Vzc2lvbl9pZCI6IjczMDBiMzNlLTUyNTItNDFmNC04ZDBiLWNlMDk1ODExODQ0NiIsImlzX2Fub255bW91cyI6ZmFsc2V9.ZRbWXLmUo96Wqbh1aVZzRDEhbIO6t78DJScxaKz7-gU"  # Replace with valid token

headers = {
    "Authorization": JWT_TOKEN,
    "Content-Type": "application/json"
}

def test_oauth_status():
    """Test OAuth status endpoint."""
    try:
        response = requests.get(f"{BASE_URL}/oauth/google-workspace/status", headers=headers)
        print(f"OAuth Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error testing OAuth status: {e}")

def test_chat_endpoint():
    """Test the main chat endpoint."""
    payload = {
        "system": "You are a helpful assistant.",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Hello, how are you?"
                    }
                ]
            }
        ],
        "tools": []
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/chat", headers=headers, json=payload)
        print(f"Chat Endpoint: {response.status_code}")
        print(f"Response: {response.text[:200]}...")  # First 200 chars
    except Exception as e:
        print(f"Error testing chat endpoint: {e}")

def test_oauth_authorize():
    """Test OAuth authorization endpoint."""
    try:
        response = requests.get(
            f"{BASE_URL}/oauth/google-workspace/authorize?redirect_uri=http://localhost:3000/admin/flux",
            headers=headers
        )
        print(f"OAuth Authorize: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error testing OAuth authorize: {e}")

if __name__ == "__main__":
    print("Testing FastAPI Server...")
    print("=" * 50)
    
    test_oauth_status()
    print("-" * 30)
    
    test_chat_endpoint()
    print("-" * 30)
    
    test_oauth_authorize()
    print("=" * 50)
    print("Testing complete!") 