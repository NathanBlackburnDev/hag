from __main__ import app
from flask import Flask, redirect, render_template, url_for, session, request, flash
import hashlib
import re
from db_connector import Database

db = Database()

# Index route
@app.route('/')
def index():
    return render_template('index.html')


# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If the user is submitting a form
    if request.method == 'POST':
        # User form data
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        location = request.form['location']

        # Format the input correctly
        location = location.capitalize()

        # Patterns for validating user input
        username_pattern = '^[A-Za-z0-9_]+$'
        # https://www.educative.io/answers/how-to-do-password-validation-in-python-using-regex
        password_pattern = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$"
        email_pattern = '^[A-Za-z0-9@. ]+$'
        location_pattern = '^[A-Z-a-z ]+$'

        # Check if account already exists
        existing_account = db.queryDB('SELECT * FROM users WHERE username = ? OR email = ?', [username, email])

        # Check user input is valid
        if existing_account:
            flash('Username or email already in use')
        elif not re.match(username_pattern, username):
            flash('Username must only be letters, numbers and underscores')
        elif not (4 < len(username) <= 14):
            flash('Username must be between 4 and 14 characters')
        elif not re.match(password_pattern, password):
            flash('Password must have 1 capital letter, 1 lowercase letter, 1 number and minimum of 8 characters')
        elif password != confirm_password:
            flash('Passwords must match')
        elif not re.match(email_pattern, email):
            flash('Please enter valid email. I.e. user@email.com')
        elif not (6 < len(email) <= 40):
            flash('Email must be between 6 and 40 characters (inclusive)')
        elif not re.match(location_pattern, location):
            flash('Please enter a valid location')
        elif not (4 < len(location) <= 60):
            flash('Location must be between 4 and 60 characters (inclusive)')
        else:
            # Hash user data
            hashed_password = hashlib.md5(str(password).encode()).hexdigest()
            hashed_email = hashlib.md5(str(email).encode()).hexdigest()

            # Insert into users table
            db.updateDB('INSERT INTO users (username, password, email, location) VALUES (?, ?, ?, ?)', [username, hashed_password, hashed_email, location])

            # Redirect user to login route
            return redirect(url_for('login'))
        
    return render_template('register.html')


#Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is submitting form
    if request.method == 'POST':
        # Get user data
        username = request.form['username']
        password = request.form['password']

        # Get user password
        user_account = db.queryDB('SELECT * FROM users WHERE username = ?', [username])

        # Check if login is correct
        if not user_account:
            flash('Account does not exist')
        else:

            # If account exists, get password and hash form password to compare
            stored_password = user_account[0][2]
            hashed_password = hashlib.md5(str(password).encode()).hexdigest()        

            if hashed_password != stored_password:
                flash('Incorrect password')
            else:
                # Add user to session dictionary
                session['user'] = username
                return redirect(url_for('index'))

    # If the user is already logged in
    if 'user' in session:
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/health_tools', methods=['GET', 'POST'])
def health_tools():
    return render_template('health_tools.html')


@app.route('/air_quality', methods=['GET', 'POST'])
def air_quality():
    return render_template('air_quality.html')


@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/weather_forecast')
def weather_forecast():
    return render_template('weather_forecast.html')


@app.route('/risk_assessment', methods=['GET', 'POST'])
def risk_assessment():
    return render_template('risk_assessment.html')


# Logout route
@app.route('/logout')
def logout():
    # Pop all session keys
    for key in list(session.keys()):
        session.pop(key)

    return render_template('index.html')