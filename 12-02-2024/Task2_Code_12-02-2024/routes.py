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
        elif not (4 <= len(username) <= 14):
            flash('Username must be between 4 and 14 characters')
        elif not re.match(password_pattern, password):
            flash('Password must have 1 capital letter, 1 lowercase letter, 1 number and minimum of 8 characters')
        elif password != confirm_password:
            flash('Passwords must match')
        elif not re.match(email_pattern, email):
            flash('Please enter valid email. I.e. user@email.com')
        elif not (6 <= len(email) <= 40):
            flash('Email must be between 6 and 40 characters (inclusive)')
        elif not re.match(location_pattern, location):
            flash('Please enter a valid location')
        elif not (4 <= len(location) <= 60):
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


# Terms & Conditions route
@app.route('/tandcs')
def tandcs():
    return render_template('tandc.html')


# Logout route
@app.route('/logout')
def logout():
    # Pop all session keys
    for key in list(session.keys()):
        session.pop(key)

    return render_template('index.html')


# Register admin route
@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    # If the admin is submitting a form
    if request.method == 'POST':
        # Admin form data
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']

        # Patterns for validating user input
        username_pattern = '^[A-Za-z0-9_]+$'
        # https://www.educative.io/answers/how-to-do-password-validation-in-python-using-regex
        password_pattern = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$"
        email_pattern = '^[A-Za-z0-9@. ]+$'

        # Check if account already exists
        existing_account = db.queryDB('SELECT * FROM admin WHERE username = ? OR email = ?', [username, email])

        # Check user input is valid
        if existing_account:
            flash('Username or email already in use')
        elif not re.match(username_pattern, username):
            flash('Username must only be letters, numbers and underscores')
        elif not (4 <= len(username) <= 14):
            flash('Username must be between 4 and 14 characters')
        elif not re.match(password_pattern, password):
            flash('Password must have 1 capital letter, 1 lowercase letter, 1 number and minimum of 8 characters')
        elif password != confirm_password:
            flash('Passwords must match')
        elif not re.match(email_pattern, email):
            flash('Please enter valid email. I.e. user@email.com')
        elif not (6 <= len(email) <= 40):
            flash('Email must be between 6 and 40 characters (inclusive)')
        else:
            # Hash user data
            hashed_password = hashlib.md5(str(password).encode()).hexdigest()
            hashed_email = hashlib.md5(str(email).encode()).hexdigest()

            # Insert into admin table
            db.updateDB('INSERT INTO admin (username, password, email) VALUES (?, ?, ?)', [username, hashed_password, hashed_email])

            # Redirect user to login route
            return redirect(url_for('admin_login'))

    return render_template('admin_register.html')


# Login admin route
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    # If admin is submitting form
    if request.method == 'POST':
        # Get admin data
        username = request.form['username']
        password = request.form['password']

        # Get admin password
        user_account = db.queryDB('SELECT * FROM admin WHERE username = ?', [username])

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
                session['admin'] = username
                return redirect(url_for('index'))

    # If the user is already logged in
    if 'admin' in session:
        return redirect(url_for('admin'))

    return render_template('admin_login.html')

# Admin index page
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    return render_template('index.html')


# Add condition route
@app.route('/add_condition', methods=['GET', 'POST'])
def add_condition():
    # If admin is submitting form
    if request.method == 'POST':
        # Get form data
        condition_name = request.form['condition_name']
        condition_desc = request.form['condition_desc']
        condition_symptom = request.form['condition_symptom']
        condition_treatment = request.form['condition_treatment']
        weather_type = request.form['weather_type']
        condition_type = request.form['condition_type']
        condition_causes = request.form['condition_causes']

        # Pattern for all input
        pattern = '^[A-Za-z0-9]+$'
        # Bullet point pattern
        bp_pattern = '^[•\sA-Za-z0-9]'

        # Check to see if condition has not alreayd been added
        existing_condition = db.queryDB('SELECT * FROM health_conditions WHERE condition_name = ?', [condition_name])

        # Check if input is valid
        if existing_condition:
            flash('Condition already added')
        elif not re.match(pattern, condition_name):
            flash('Condition name must only be letters and numbers')
        elif not (2 <= len(condition_name) <= 100):
            flash('Condition must be between 2 and 100 characters (inclusive)')
        elif not re.match(pattern, condition_desc):
            flash('Condition description must only be letters and numbers')
        elif not (12 <= len(condition_desc) <= 1000):
            flash('Condition description must be between 12 and 1000 characters (inclusive)')
        elif not re.match(bp_pattern, condition_treatment):
            flash('Condition treatement must only be letters and numbers')
        elif not (4 <= len(condition_treatment) <= 1000):
            flash('Condition treatment must be between 4 and 1000 characters (inclusive)')
        elif not weather_type:
            flash('Must select weather type')
        elif not condition_type:
            flash('Must enter condition type')
        elif not re.match(bp_pattern, condition_symptom):
            flash('Symptoms must only be letters and numbers')
        elif not (4 <= len(condition_symptom) <= 1000):
            flash('Condition symptoms must be between 4 and 1000 characters (inclusive)')
        elif not re.match(bp_pattern, condition_causes):
            flash('Causes must only be letters and numbers')
        elif not (4 <= len(condition_causes) <= 1000):
            flash('Condition causes must be between 4 and 1000 characters (inclusive)')
        else:
            pass


    return render_template('add_condition.html')
