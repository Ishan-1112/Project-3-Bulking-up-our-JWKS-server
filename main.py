# Import necessary libraries
from flask import Flask, jsonify, request
import os
import bcrypt
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt
import sqlite3

# Initialize Flask application
app = Flask(__name__)

# Set AES encryption key from environment variable
AES_KEY = os.getenv('NOT_MY_KEY')

# Define database connection and cursor
conn = sqlite3.connect('database.db', check_same_thread=False)
c = conn.cursor()

# Create users table if not exists
c.execute('''CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP      
)''')

# Create auth_logs table if not exists
c.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,  
    FOREIGN KEY(user_id) REFERENCES users(id)
)''')

# Encrypt and decrypt functions using AES
def encrypt(text):
    # Implement AES encryption here
    pass

def decrypt(text):
    # Implement AES decryption here
    pass

# Update /auth endpoint to log authentication requests
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired')
    if expired:
        c.execute('SELECT * FROM keys WHERE exp <= ?', (datetime.utcnow().timestamp(),))
    else:
        c.execute('SELECT * FROM keys WHERE exp > ?', (datetime.utcnow().timestamp(),))

    key_row = c.fetchone()
    key = serialization.load_pem_private_key(decrypt(key_row[1]), password=None, backend=default_backend())

    # Convert the kid to a string if it's not already
    kid = str(key_row[0])

    # Log authentication request
    request_ip = request.remote_addr
    user_id = request.json.get('username')  # Assuming username is sent in request JSON
    c.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request_ip, user_id))
    conn.commit()

    # Sign the JWT token using the RSA private key
    token = jwt.encode({'some': 'payload'}, key, algorithm='RS256', headers={'kid': kid})
    return jsonify({'access_token': token})


# Implement /register endpoint for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')

    # Generate secure password using bcrypt
    password = generate_secure_password().decode('utf-8')  # bcrypt returns bytes, convert to string
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Store user details in the database
    c.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)', (username, hashed_password.decode('utf-8'), email))
    conn.commit()

    return jsonify({'password': password}), 201

# Define the '/' route
@app.route('/')
def index():
    return 'Welcome to the main page!'

# Generate a secure password
def generate_secure_password():
    # Generate secure password using any secure method
    pass

if __name__ == "__main__":
    app.run(port=8080)
