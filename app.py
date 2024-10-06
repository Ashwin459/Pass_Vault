import random
import string
from pymongo import MongoClient
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash, request, jsonify
from flask_session import Session
import bcrypt
import re
from cryptography.fernet import Fernet
import requests
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

def generate_key():
    return Fernet.generate_key()

#function to hash password
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def encrypt_password(key, password):
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password

# Decrypt the password
def decrypt_password(key, encrypted_password):
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password

uri = "mongodb+srv://ashwinkon98:ywqZWZLh7jGKTk1c@passvault.ionto.mongodb.net/?retryWrites=true&w=majority&appName=PassVault"

# Create a new MongoDB client
client = MongoClient(uri, server_api=ServerApi('1'))

#connect to MongoDb database 

db = client["PassVault"]
passwords_collection = db["generated_passwords"]
user_account_collection = db["user_account"]
users_password_collection = db["user_passwords"]

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ashwin'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)




@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if request.method == 'POST':
        username = session.get('username')
        
        acc_name = request.form['acc_name']  # Account name (e.g., "insta")
           
        acc_username = request.form['acc_username']  # User's account username
        password = request.form['acc_password']   # User's password
        confirm_pass = request.form['cpass']      # Password confirmation

        if password != confirm_pass:
            flash("Passwords do not match. Please try again.", "add_password_error")
            return redirect(url_for('add_password'))

        # Retrieve the encryption key for the user
        key_doc = user_account_collection.find_one({"username": username})
        if key_doc is None:
            # If the user doesn't have a key, generate one and store it
            key = generate_key()
            user_account_collection.insert_one({"username": username, "key": key})
        else:
            key = key_doc['key']

        # Encrypt the password
        encrypted_password = encrypt_password(key, password)

        # Create the password document
        password_data = {
            "username": username,        # The user's username
            "acc_name": acc_name,        # The name of the account (e.g., "insta")
            "acc_username": acc_username, # The username for the account
            "encrypted_password": encrypted_password  # Encrypted password
        }

        # Store the password data in the database
        users_password_collection.insert_one(password_data)
        flash("Password added successfully!", "add_password_success")
        return redirect(url_for('add_password'))  # Redirect back to the add password page

    return render_template('dashboard.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


#function to check password strength

@app.route('/check-password-strength', methods=['POST'])
def check_password_strength():
    password = request.form.get('password')

    # Basic password checking logic
    if not password:
        flash("Password cannot be empty.", 'error')
        return "Password cannot be empty."

    # Add password strength checks here...
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Password should contain lowercase letters.")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Password should contain uppercase letters.")

    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Password should contain numbers.")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Password should contain special characters.")

    strength = "Very Weak"
    if score == 5:
        strength = "Very Strong"
    elif score == 4:
        strength = "Strong"
    elif score == 3:
        strength = "Fair"
    elif score == 2:
        strength = "Weak"

    return f"Password Strength: {strength} Suggestions: {', '.join(feedback)}"
# Function to generate a strong password
def generate():
    special_characters = "!@#$%^&*()"
    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(special_characters)
    ]
    
    while len(password) < 15:
        password.append(random.choice(string.ascii_letters + string.digits + special_characters))
    
    random.shuffle(password)
    password_str = ''.join(password)
    if not passwords_collection.find_one({"password": password_str}):
        passwords_collection.insert_one({"password": password_str})
        return password_str
    

@app.route('/submit', methods=['POST'])
def create_acc():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    cpass = request.form.get('cpass')

    # Email validation using regex
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    if not re.match(pattern, email):
        flash("Invalid email format. Please try again.", 'create_account_error')
        return redirect(url_for('index'))

    # Password match validation
    if password != cpass:
        flash("Passwords do not match. Please try again.", 'create_account_error')
        return redirect(url_for('index'))

    # Password length validation
    if len(password) < 8:
        flash("Password should be at least 8 characters long.", 'create_account_error')
        return redirect(url_for('index'))

    # Hash the password
    hashed_password = hash_password(password)

    # Store the user data in the database
    user_data = {
        "username": username,
        "email": email,
        "hashed_password": hashed_password,
        "key": generate_key()
    }

    user_account_collection.insert_one(user_data)
    flash("Account created successfully!", 'create_account_success')
    return redirect(url_for('index'))



# Function to handle user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find user by username
        user = user_account_collection.find_one({"username": username})

        # Check if user exists and verify password
        if user and bcrypt.checkpw(password.encode('utf-8'), user['hashed_password']):
            session['username'] = username  # Store username in the session
            session['email'] = user['email']
            flash("Logged in successfully!", 'login_success')
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials, please try again.", 'login_error')
            return redirect(url_for('index'))

    return render_template('index.html')
  # Render login template on GET request


@app.route('/view_pass')
def view_pass():
    # Ensure the user is logged in
    username = session.get('username')
    if not username:
        flash("You need to be logged in to view your passwords.", "login_error")
        return redirect(url_for('index'))  # Redirect to login if not logged in

    # Retrieve all stored passwords for the logged-in user
    stored_passwords = users_password_collection.find({"username": username})

    decrypted_passwords = []
    for password_data in stored_passwords:
        # Retrieve the encryption key for the user
        key_doc = user_account_collection.find_one({"username": username})
        if key_doc:
            key = key_doc['key']
            decrypted_password = decrypt_password(key, password_data['encrypted_password'])
            decrypted_passwords.append({
                'acc_name': password_data['acc_name'],
                'acc_username': password_data['acc_username'],
                'decrypted_password': decrypted_password
            })

    # Pass the decrypted passwords to the template
    return render_template('dashboard.html', passwords=decrypted_passwords)

@app.route('/logout', methods=['POST'])
def logout():
    # Clear the session data
    session.clear()  # This will remove all session data, including the username
    flash("Logged out successfully!", "logout_success")  # Flash a success message
    return redirect(url_for('index'))




# Route for the main page
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        gen_password = generate() 
        flash(f'Generated Password: {gen_password}', 'generate_password')
        return redirect(url_for('index'))  

    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)