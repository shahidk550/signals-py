#TODO 1. create a new API set up.
#2. go to each function and create a route that works with API - change api/register

'''
1. resiter user > post to loccalhost 8080/auth/register > payload email & passw. header content type json, validation 

2. display message to user success > do not naviagte user. 

3. create login function > auth/login/ > payload (email, password) > check errors > success status code  - parse returned json and get access token and refresh token. 

4. Edit register route and redirect to login page on succesful creation of user 

5. Find out how to store the access token and refresh token  (http cookie/memory)

6. use access token to create a signal using access token in authorisation header 

7. check to see if access token has expired > if has > use auth/refresh api to get new one.

8. if refresh token expired tell user to log in again. 
'''


from flask import Flask, render_template, redirect, request, flash, url_for, session #Flask is the main tool to help build the website/app and also manage the pages, requests and flow of info.
from flask_scss import Scss #makes it easier to manage css
from flask_sqlalchemy import SQLAlchemy #Db to manage information 
from flask_wtf import FlaskForm #Helps to create and manage the forms on the website - text boxes, passwords, buttons etc
from wtforms import StringField, PasswordField, SubmitField, TextAreaField #Rules for the forms
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp #Rules we can set for the forms 
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user #Helps to manage the logins, logouts and track who is using the site.
from sqlalchemy.sql import func #Access to dcv functions like sorting data 
import bcrypt #Tool to securely store the passwords and hash them
from datetime import datetime #Allows us to work with date and times
import re #Checking for patterns ie if ETA date looks like a date
import requests 
import logging
from flask_wtf.csrf import CSRFProtect
import json 
import os 
from dotenv import load_dotenv

# Load environment variables (e.g., LOG_FILENAME for logging)
load_dotenv()
log_filename = os.getenv('LOG_FILENAME', 'api_app.log')

# Configure logging
log_filename="api_app.log" #TODO this should be read from .env file 
logging.basicConfig(level=logging.INFO, filename=log_filename, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# App setup
app = Flask(__name__, template_folder='templates') #Creates the web application 
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db" #Tells the app where to find the db
app.config['SECRET_KEY'] = 'your-unique-secret-key-1234567890'  # Replace with your unique key!
app.config['SESSION_COOKIE_SECURE'] = False  # Disabled for local testing (no HTTPS), in real website turn to TRUE
csrf = CSRFProtect(app)
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes session expiry as per token 

Scss(app) #App will use Scss for styling CSS
db = SQLAlchemy(app) #Connects the app the the db using Flask-SQLAlchemy

# Initialize Flask-Login 
login_manager = LoginManager() #Sets up the login manager 
login_manager.init_app(app) #Connects the login manager to Flask app/site
login_manager.login_view = 'api_login' #Tells Flask-Login where to the send users if they need to login.

# User model - represents the user in the table of db
class User(db.Model, UserMixin): #Blueprint for how we store the data - each user will have id, email. pw, provider and role (i.e admin). Inherets 'db.Model and 'UserMixin' (from Flask-Login, providing default implementations for user properties).
    id = db.Column(db.Integer, primary_key=True) 
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)  # Stores hashed password
    provider = db.Column(db.String(20), nullable=True)  # For future OAuth (e.g., 'google', 'github')
    role = db.Column(db.String(10), nullable=False, default='user')  # 'user' or 'admin'

# Data Class - Determines the rows of data in the db
class MyTask(db.Model): # Defines a Python class named 'MyTask' that represents the 'mytask' table in database.
    id = db.Column(db.Integer, primary_key=True) # Unique identifier for each task
    signal_from = db.Column(db.String(100), nullable=False) # Stores the source of the signal (e.g., a location or system)
    commodity = db.Column(db.String(100)) # Stores the type of commodity related to the signal
    departure = db.Column(db.String(100)) 
    arrival_port = db.Column(db.String(100))
    eta = db.Column(db.String(100))
    complete = db.Column(db.DateTime, nullable=True, default=None) # Stores the date and time when the task was completed
    created = db.Column(db.DateTime, default=datetime.utcnow) # Stores the date and time when the task was created
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Foreign key linking this task to a specific user in the 'user' table. 'db.ForeignKey('user.id')' establishes this link, and 'nullable=False' means every task must belong to a user.
    user = db.relationship('User', backref='tasks') # Creates a relationship between the 'MyTask' and 'User' models. 'backref='tasks'' allows you to access the list of tasks associated with a user object (e.g., `user.tasks`).

    def __repr__(self) -> str: # A special method that defines how a 'MyTask' object should be represented as a string (useful for debugging and logging).
        return f"Task {self.id} - {self.signal_from}"

# Create the Forms
class SignalForm(FlaskForm): # Defines a form for creating or editing 'MyTask' objects. It inherits from 'FlaskForm'.
    signal_from = StringField('Signal From', validators=[DataRequired(), Length(max=100)]) #A text field for the signal source, requires data and can be up to 100 characters.
    commodity = StringField('Commodity', validators=[Length(max=100)])
    departure = StringField('Departure', validators=[Length(max=100)])
    arrival_port = StringField('Arrival Port', validators=[Length(max=100)])
    eta = StringField('ETA (dd-mm-yyyy)', validators=[Length(max=100), Regexp(r'^\d{2}-\d{2}-\d{4}$|^$', message="ETA must be in DD-MM-YYYY format (e.g., 04-05-2023).")])
    submit = SubmitField('Submit') # A submit button for the form.

class RegisterForm(FlaskForm):# Defines a form for user registration.
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)]) # An email field, requires data, must be a valid email format, and can be up to 120 characters.
    password = PasswordField('Password', validators=[DataRequired(), Length(min=11)])  # A password field, requires data and must be at least 8 characters long.
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')]) # A password confirmation field, requires data and must be equal to the value entered in the 'password' field.
    submit = SubmitField('Register') # A submit button for the registration form.


class APIRegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=11)])
    submit = SubmitField('Register via API')


class LoginForm(FlaskForm): # Defines a form for user login.
    email = StringField('Email', validators=[DataRequired(), Email()]) 
    password = PasswordField('Password', validators=[DataRequired(), Length(min=11)])
    submit = SubmitField('Login')


class SignalSubmitForm(FlaskForm):
    # Form for submitting signals to the API
    isn_slug = StringField('ISN Slug', validators=[DataRequired(), Length(max=100)])
    signal_type_slug = StringField('Signal Type Slug', validators=[DataRequired(), Length(max=100)])
    sem_ver = StringField('Semantic Version', validators=[DataRequired(), Regexp(r'^\d+\.\d+\.\d+$', message="Must be in format X.Y.Z (e.g., 0.0.1)")])
    local_ref = StringField('Local Reference', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Content (JSON)', validators=[DataRequired()])
    correlation_id = StringField('Correlation ID', validators=[Length(max=100)])
    submit = SubmitField('Submit Signal')



# Flask-Login user manager 
@login_manager.user_loader # A decorator that registers a function to load a user from the database based on their ID, which Flask-Login stores in the user's session.
def load_user(user_id): # This function takes a user ID and should return the corresponding user object from the database
    return User.query.get(int(user_id)) # Queries the 'User' table in the database for a user with the given ID and returns the user object.

#new api function ------------------------------------------------------------


def refresh_access_token():
    # Calls POST /auth/token to refresh access_token using current token and refresh token cookie
    # Returns True if successful, False if refresh token is invalid
    logger.info('Attempting to refresh access token')
    if 'access_token' not in session:
        logger.warning('No access_token in session for refresh')
        return False

    try:
        # Send refresh request to API server
        # Current (possibly expired) access_token is used for identification
        # Browser automatically sends refresh token cookie (HTTP-only)
        api_url = "http://localhost:8080/auth/token"
        headers = {
            "Authorization": f"Bearer {session['access_token']}",
            "Content-Type": "application/json"
        }
        response = requests.post(api_url, headers=headers, timeout=10)
        logger.info(f"Token refresh - Status: {response.status_code}, Body: {response.text}")

        if response.status_code == 200:
            # Extract new access_token and user data
            data = response.json()
            session['access_token'] = data.get('access_token')  # New JWT
            session['account_id'] = data.get('account_id')      # Update account_id
            session['role'] = data.get('role')                  # Update role
            # Note: email not returned, retained from login
            logger.info('Token refresh - Successful')
            return True

        elif response.status_code == 401:
            # Invalid or expired refresh token
            logger.warning('Token refresh - Unauthorized: Invalid refresh token')
            session.clear()  # Clear session to force login
            return False

        else:
            # Other errors (400, 500)
            logger.warning(f"Token refresh - Failed: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        logger.error(f"Token refresh - Connection error: {str(e)}")
        return False


@app.route('/api/register', methods=['GET', 'POST']) # Decorator that links the URL '/register' to the 'register' function. It handles both GET requests (when a user visits the page) and POST requests (when the user submits the registration form).
def register(): #Handles the showing and processing form when ouser submits it.
    logger.debug(f'In new api register function')
    form = APIRegisterForm() # Creates an instance of the 'API Register Form'.
    #TODO check if user in auth already
    if form.validate_on_submit(): # Checks if the registration form has been submitted (POST request) and if all the validators in the form have passed.
        logger.info('In API register function')
        email = form.email.data
        password = form.password.data


        try:
            api_url =  "http://localhost:8080/auth/register"
            response = requests.post(
                api_url, 
                json={"email" : form.email.data, "password" : form.password.data}, 
                headers={"Content-Type" : "application/json"}, 
                timeout=10
            )
            logger.info(f"API register - Status: {response.status_code}, Body: {response.text}")
            
            if response.status_code == 201:
                flash('Registration Successful! Please log in now', 'success')
                logger.info(f"API register - Success for email {email}")
                return redirect(url_for('api_login')) #login page. 

            elif response.status_code == 409:
                flash('Email already registered', 'error')
                logger.warning(f"API register - Email already registered: {email}")
            
            elif response.status_code == 400:
                flash('Invalid email or password format')
                logger.warning(f"API register - Invalid input: {response.text}")

            else: 
                flash('Registration failed: API error', 'error')
            logger.warning(f"API register - Failed: {response.text}")
            return render_template('api_register.html', form=form)
    
        except requests.exceptions.RequestException as e:
            flash('Failed to connect to API', 'error')
            logger.error(f"API register - Connection error: {str(e)}")
            return render_template('api_register.html', form=form)

    else:
        logger.debug(f"API register - Form validation failed: {form.errors}")
    
    return render_template('api_register.html', form=form)


'''
#Smaller registration code for testing without the validation.

@app.route('/api/register', methods=['GET', 'POST'])
def register():
    form = APIRegisterForm()
    if form.validate_on_submit():
        logger.debug(f"Email: {form.email.data}, Password: {form.password.data}")
        try:
            api_url =  "http://localhost:8080/auth/register"
            logger.debug(f"Attempting POST to: {api_url}")
            response = requests.post(api_url, json={"email" : form.email.data, "password" : form.password.data}, headers={"Content-Type" : "application/json"}, timeout=10)
            logger.info(f"API register - Status: {response.status_code}, Body: {response.text}")
            # ... rest of your response handling ...
        except requests.exceptions.RequestExceptions as e:
            logger.error(f"Connection error: {e}")
            # ... rest of your error handling ...
        return render_template('api_register.html', form=form) # Keep this for now
    return render_template('api_register.html', form=form)
'''

#API Log in function 
@app.route('/api/login', methods=['GET', 'POST'])
def api_login():# Handles user login via API server[](http://localhost:8080/auth/login)
    # Generates and stores access_token in session
    logger.info('In API login function')
    form = LoginForm()
    if form.validate_on_submit():
        logger.info(f"API login - Form validated, email: {form.email.data}")
        email = form.email.data
        password = form.password.data

        try:# Send login request to API server to obtain access_token
            api_url = "http://localhost:8080/auth/login"
            response = requests.post (
                api_url,
                json={"email": email, "password": password},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            logger.info(f"API login - Status: {response.status_code}, Body: {response.text}")

            if response.status_code == 200: # Extract access_token and user data from API response
                data = response.json()
                access_token = data.get('access_token') # JWT for authentication
                account_id = data.get('account_id')
                role = data.get('role')


                # Store access_token and user data in Flask session
                # Session is server-side, with a signed cookie sent to the browser
                # SECRET_KEY signs the session cookie for security
                session['access_token'] = access_token # Used to authenticate /api/dashboard
                session['account_id'] = account_id   # Links to user identity
                session['role'] = role      # Used in dashboard.html
                session['email'] = email    # Used in dashboard.html

                flash ('Login successful!', 'success')
                logger.info(f"API login - Successful for email: {email}, role: {role}")
                # Redirect to /api/dashboard, where access_token is checked
                return redirect(url_for('api_dashboard')) #Placeholder

            elif response.status_code == 400:
                flash('Invalid email or password format,', 'error')
                logger.warning(f"API login - Invalid input: {response.text}")

            elif response.status_code == 401: 
                flash('Invalid email or password.', 'error')
                logger.warning(f"API login - Unexpected status {response.status_code}: {response.text}")
            
            return render_template('api_login.html', form=form)

        except requests.exceptions.RequestException as e:
            flash('Failed to connect to API.', 'error')
            logger.error(f"API login - Connection error: {str(e)}")
            return render_template('api_login.html', form=form)

    else: 
        logger.debug(f"API login - Form Validaton Failed: {form.errors}")

    return render_template('api_login.html', form=form)



@app.route('/api/dashboard')

# Protected route requiring access_token in session
    # Renders dashboard.html with user data from session
def api_dashboard():
    # Protected route requiring access_token in session
    # Renders dashboard.html with user data from session and signal submission form
    logger.info(f"Template folder: {app.template_folder}")
    template_path = os.path.join(app.template_folder, 'api_dashboard.html')
    logger.info(f"Checking template: {template_path}, exists: {os.path.exists(template_path)}")
    static_path = os.path.join(app.static_folder, 'styles.css')
    logger.info(f"Checking static file: {static_path}, exists: {os.path.exists(static_path)}")

    # Check if access_token exists in session to authenticate user
    # Browser sends session cookie, which Flask verifies using SECRET_KEY
    if 'access_token' not in session:
        flash('Please log in.', 'error')
        # Redirect to /api/login if no token, ending request
        return redirect(url_for('api_login'))

    # Pass SignalSubmitForm to dashboard.html for signal submission
    form = SignalSubmitForm()
    # Access session data for rendering dashboard
    # email and role are passed to dashboard.html for display
    return render_template('api_dashboard.html', email=session.get('email'), role=session.get('role'), form=form)


@app.route('/api/submit_signal', methods=['POST'])
def submit_signal():
    # Handles signal submission to API server[](http://localhost:8080/isn/{isn_slug}/signal_types/{signal_type_slug}/v{sem_ver}/signals)
    # Uses access_token from session for authentication
    # Refreshes token on 401 "access_token_expired" and retries
    logger.info('In API submit_signal function')
    form = SignalSubmitForm()
    if form.validate_on_submit():
        logger.info(f"API submit_signal - Form validated, isn_slug: {form.isn_slug.data}")

        # Check if access_token exists in session
        if 'access_token' not in session:
            flash('Please log in to submit signals.', 'error')
            return redirect(url_for('api_login'))

        def send_signal_request():
            # Helper function to send signal request (allows retry after refresh)
            try:
                # Parse content as JSON
                content = json.loads(form.content.data)
            except json.JSONDecodeError:
                flash('Invalid JSON format in content.', 'error')
                logger.warning('API submit_signal - Invalid JSON in content')
                return redirect(url_for('api_dashboard'))

            # Construct signal payload
            signal = {
                "content": content,
                "local_ref": form.local_ref.data
            }
            if form.correlation_id.data:
                signal["correlation_id"] = form.correlation_id.data

            payload = {
                "signals": [signal]
            }

            # Construct API URL
            api_url = f"http://localhost:8080/api/isn/{form.isn_slug.data}/signal_types/{form.signal_type_slug.data}/v{form.sem_ver.data}/signals"
            logger.info(f"API submit_signal - Sending to URL: {api_url}, Payload: {json.dumps(payload)}")


            # Send POST request to API server with access_token
            headers = {
                "Authorization": f"Bearer {session['access_token']}",
                "Content-Type": "application/json"
            }
            response = requests.post(
                api_url,
                json=payload,
                headers=headers,
                timeout=10
            )
            return response

        # Attempt to send signal
        response = send_signal_request()
        logger.info(f"API submit_signal - Status: {response.status_code}, Body: {response.text}")

        if response.status_code == 401 and 'access_token_expired' in response.text.lower():
            # Access token expired; attempt to refresh
            if refresh_access_token():
                # Retry signal submission with new token
                response = send_signal_request()
                logger.info(f"API submit_signal - Retry status: {response.status_code}, Body: {response.text}")
            else:
                # Refresh failed (invalid refresh token)
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('api_login'))

        # Handle response
        if response.status_code == 201:
            # Signal stored successfully
            data = response.json()
            flash(f"Signal submitted successfully! Stored signals: {len(data.get('stored_signals', []))}", 'success')
            logger.info(f"API submit_signal - Success for local_ref: {form.local_ref.data}")
            return redirect(url_for('api_dashboard'))

        elif response.status_code == 400:
            # Handle validation errors (e.g., missing fields, invalid correlation_id)
            error_msg = response.json().get('error', 'Invalid request')
            if 'invalid_correlation_id' in response.text:
                error_msg = 'Invalid correlation ID: must reference an existing signal of the same type.'
            flash(f"Submission failed: {error_msg}", 'error')
            logger.warning(f"API submit_signal - Bad request: {response.text}")

        elif response.status_code == 401:
            # Other unauthorized errors (e.g., invalid token, no ISN permission)
            flash('Unauthorized: Invalid token or insufficient permissions.', 'error')
            logger.warning('API submit_signal - Unauthorized')
            return redirect(url_for('api_dashboard'))

        elif response.status_code == 404:
            # ISN, signal type, or version not found
            flash('Submission failed: ISN or signal type not found. Please check the ISN and signal type.', 'error')
            logger.warning(f"API submit_signal - Not found: {response.text}")

        else:
            # Other errors (e.g., 500)
            flash('Submission failed: API server error.', 'error')
            logger.warning(f"API submit_signal - Failed: {response.text}")

        return redirect(url_for('api_dashboard'))

    else:
        logger.debug(f"API submit_signal - Form validation failed: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {field}: {error}", 'error')
        return redirect(url_for('api_dashboard'))



'''

#Defines the web address (/register) for the registration page
@app.route('/todo/register', methods=['GET', 'POST']) # Decorator that links the URL '/register' to the 'register' function. It handles both GET requests (when a user visits the page) and POST requests (when the user submits the registration form).
def old_register(): #Handles the showing and processing form when user submits it.
    if current_user.is_authenticated: # Checks if the current user is already logged in. 'current_user' is provided by Flask-Login.
        return redirect(url_for('index')) # If logged in, redirects the user to the main page (route named 'index').
    form = RegisterForm() # Creates an instance of the 'RegisterForm'.
    print(f"Request method: {request.method}") # Prints the HTTP method of the current request (GET or POST) for debugging.
    print(f"Form data: {request.form}") # Prints the data submitted in the form for debugging.
    print(f"Session data: {session.get('csrf_token', 'No CSRF token in session')}") # Prints the CSRF token from the session (used for security against cross-site request forgery) for debugging.
    if form.validate_on_submit(): # Checks if the registration form has been submitted (POST request) and if all the validators in the form have passed.
        print("Form validated successfully") # Prints a success message if the form is valid.
        # Check if email exists
        if User.query.filter_by(email=form.email.data).first(): # Queries the 'User' table to see if a user with the entered email already exists. '.first()' returns the first matching user or None.
            flash('Email already taken.', 'error') # If the email exists, it displays an error message to the user using Flask's 'flash' system.
            return render_template('register.html', form=form) # Re-renders the registration form with the error message.
        # Hash password
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()) # Hashes the user's password using bcrypt. It first encodes the password as bytes and then generates a salt (random data) to make the hash more secure.
        user = User(  # Creates a new 'User' object to be stored in the database.
            email=form.email.data, # Sets the email of the new user.
            password=hashed_password.decode('utf-8'), # Sets the hashed password of the new user (decoding it back to a string for storage).
            provider='local',  # Sets the registration provider as 'local' (as opposed to OAuth).
            role='user'  # Sets the default role for a new user as 'user'.
        )
        try: # Starts a 'try' block to handle potential database errors.
            db.session.add(user) # Adds the new 'User' object to the database session (staging it to be saved).
            db.session.commit() # Commits the changes to the database, actually saving the new user.
            flash('Registration successful! Please log in.', 'success') # If registration is successful, displays a success message.
            print("User registered, redirecting to login") # Prints a log message.
            return redirect(url_for('login')) # Redirects the user to the login page.
        except Exception as e: # Catches any exceptions (errors) that might occur during database operations.
            db.session.rollback() # If an error occurred, it rolls back the database session to its previous state, preventing partial saves.
            flash(f'Error: {str(e)}', 'error') # Displays a generic error message to the user.
            print(f"Database error: {str(e)}") # Prints the specific database error to the console for debugging.
            return render_template('register.html', form=form) # Re-renders the registration form with the error message.
    else: # If the form validation fails (e.g., passwords don't match, email is invalid).
        print("Form validation failed") # Prints a log message indicating validation failure.
        print(f"Form errors: {form.errors}") # Prints the specific validation errors for debugging.
    return render_template('register.html', form=form) # Renders the registration form (for the initial GET request or if validation fails).


@app.route('/todo/login', methods=['GET', 'POST'])  # Decorator for the login page URL, handling both displaying the form (GET) and processing the login attempt (POST).
def login(): # Handles showing the login form and checking user credentials upon submission.
    if current_user.is_authenticated: # Checks if the current user is already logged in.
        return redirect(url_for('index')) # If logged in, redirects to the main page.
    form = LoginForm() # Creates an instance of the 'LoginForm'.
    if form.validate_on_submit(): # Checks if the login form has been submitted and is valid.
        user = User.query.filter_by(email=form.email.data).first() # Queries the 'User' table for a user with the entered email.
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')): # Checks if a user with the given email exists AND if the entered password (encoded as bytes) matches the hashed password stored in the database.
            login_user(user) # Logs the user in using Flask-Login, which sets up the user's session.
            return redirect(url_for('index'))  # Redirects the logged-in user to the main page.
        flash('Invalid email or password.', 'error') # If the login fails (wrong email or password), displays an error message.
    return render_template('login.html', form=form) # Renders the login form (for the initial GET request or if login fails).

@app.route('/todo/logout') # Decorator for the logout URL.
@login_required # Flask-Login decorator that ensures only logged-in users can access this route.
def logout(): # Handles the user logout process.
    logout_user() # Logs the current user out using Flask-Login, clearing their session.
    flash('You have been logged out.', 'success')  # Displays a success message.
    return redirect(url_for('login')) # Redirects the user back to the login page.

#Main page where users can see list of signals 
@app.route("/todo/list", methods=["POST", "GET"]) # if user visits [GET] show signals. If user submits a form [POST] if valid create new signal.
@login_required # Ensures only logged-in users can access this page.
def index(): # Handles displaying the list of signals and adding new ones.
    form = SignalForm() # Creates an instance of the 'SignalForm' for adding new signals.
    if current_user.role == 'admin': # Checks if the current user's role is 'admin'.
        tasks = MyTask.query.order_by(MyTask.eta.asc().nullslast()).all() #If the user is an admin, fetches all tasks from the database, ordered by their ETA (earliest first, with null ETAs last).
    else: # If the user is not an admin (their role is likely 'user')
        tasks = MyTask.query.filter_by(user_id=current_user.id).order_by(MyTask.eta.asc().nullslast()).all() #Get the data/signals from table named Mytask but only of those matching user_id and sort them by eta, ascencing (asc) order including those with no ETA
    print(f"Current user: {current_user.email}, Role: {current_user.role}, ID: {current_user.id}") # Prints information about the currently logged-in user for debugging.
    print(f"Retrieved tasks: {[f'Task {task.id} - {task.signal_from} (User ID: {task.user_id})' for task in tasks]}") # Prints a list of the retrieved tasks for debugging.
    if request.method == "POST": # Checks if the request method is POST (meaning a form has been submitted).
        print(f"POST form data: {request.form}") # Prints the data from the submitted form for debugging.
        if form.validate_on_submit(): # Checks if the submitted form data is valid according to the validators defined in the 'SignalForm' class.
            eta_str = form.eta.data.strip() # Gets the ETA data from the form and removes any leading or trailing whitespace.
            if eta_str: # Checks if the ETA string is not empty.
                try: # Starts a 'try' block to handle potential errors when converting the ETA string to a datetime object.
                    datetime.strptime(eta_str, '%d-%m-%Y') # Attempts to convert the ETA string into a datetime object based on the 'dd-mm-yyyy' format. If the format is incorrect, it will raise a ValueError.
                except ValueError: # Catches the ValueError if the ETA string is not in the expected format.
                    flash('Invalid ETA date (e.g., 32-01-2025 is not valid).', 'error') # Displays an error message to the user.
                    print("ETA validation failed") # Prints a log message indicating ETA validation failure.
                    return render_template('index.html', tasks=tasks, form=form) # Re-renders the main page with the current tasks and the form, including the error message.
            try: # Starts a 'try' block to handle potential database errors during task creation.
                new_task = MyTask( # Creates a new 'MyTask' object with the data from the submitted form.
                    signal_from=form.signal_from.data,
                    commodity=form.commodity.data,
                    departure=form.departure.data,
                    arrival_port=form.arrival_port.data,
                    eta=eta_str if eta_str else None,  # If eta_str has a value, use it; otherwise, set ETA to None.
                    complete=None, # Initially, the task is not complete.
                    created=datetime.utcnow(), # Sets the creation timestamp to the current UTC time.
                    user_id=current_user.id # Links the new task to the ID of the currently logged-in user.
                )
                db.session.add(new_task) # Adds the new task to the database session.
                db.session.commit() # Commits the changes to the database, saving the new task.
                flash('Signal added successfully.', 'success') # Displays a message to the user indicating that the signal was added successfully.
                print(f"Signal created: {new_task.__repr__()}") # Prints a message to the console 
                return redirect("/list") # Sends the user's browser to the '/list' URL
            except Exception as e: #This starts a block of code that will handle any errors that might occur in the 'try' block above (e.g., issues with the database). 'e' will contain information about the error.
                db.session.rollback() # If an error occurred, this line undoes any changes that were attempted in the database session
                flash(f'Error: {str(e)}', 'error') # Displays an error message to the user, including the specific error that occurred. 'error' is another category for the message, usually styled to indicate a problem.
                print(f"Database error: {str(e)}") # Prints the specific database error to the console for debugging.
        else: # This 'else' block runs if the `if form.validate_on_submit():` condition was false, meaning the submitted form data was not valid according to the rules set.
            print(f"Form validation failed: {form.errors}") # Prints the specific validation errors to the console
        return render_template('index.html', tasks=tasks, form=form) # Regardless of whether the form was submitted or if it was invalid, this line renders the 'index.html' template, passing the list of tasks and the form object to it so they can be displayed on the webpage.
    return render_template('index.html', tasks=tasks, form=form) # This line is reached if the request method was GET (the user just visited the '/list' page), and it renders the 'index.html' template to display the initial list of tasks and the empty form for adding new signals.

#Allows logged in users to delete thier own signals 
@app.route("/todo/delete/<int:id>") # This decorator defines a new URL route '/delete/<int:id>'. When a user visits a URL like '/delete/123', the 'delete' function will be executed, and 'id' will be the number in the URL (e.g., 123). '<int:id>' specifies that 'id' should be treated as an integer.
@login_required # Ensures that only logged-in users can access this URL.
def delete(id): # This function handles the deletion of a specific signal based on its ID.
    task = MyTask.query.get_or_404(id) # This line tries to find a 'MyTask' object in the database with the given 'id'. If a task with that ID is found, it's stored in the 'task' variable. If no task is found, it automatically returns a 404 (Not Found) error to the user.
    if task.user_id != current_user.id:  # This checks if the 'user_id' of the task (the user who created it) is different from the ID of the currently logged-in user.
        flash('Unauthorised action: You can only delete your own signal') # If the task doesn't belong to the current user, it displays an error message.
        return redirect(url_for('index')) # And then redirects the user back to the main list of signals.
    try: # Starts a 'try' block to handle potential database errors during deletion.
        db.session.delete(task)  # This marks the 'task' object for deletion in the database session.
        db.session.commit() # This line actually executes the deletion in the database.
        flash('Signal deleted successfully.', 'success') # Displays a success message to the user.
        return redirect("/list") # Redirects the user back to the list of signals, which should now be updated.
    except Exception as e: # Catches any errors that might occur during the database operations.
        db.session.rollback()  # If an error occurred, this line undoes any changes in the session.
        flash(f'Error: {str(e)}', 'error') # Displays an error message to the user.
        tasks = MyTask.query.filter_by(user_id=current_user.id).order_by(MyTask.eta.asc().nullslast()).all() # If there was an error, it re-fetches the user's tasks to ensure the page can still be displayed.
        return render_template('index.html', tasks=tasks, form=SignalForm()) # Renders the main list page again, possibly with the error message.


#Allows logged in users to edit their own signals and updates existing data and database. 
@app.route("/todo/edit/<int:id>", methods=["GET", "POST"]) # This decorator defines a URL route '/edit/<int:id>' that handles both GET requests (to display the edit form) and POST requests (to submit the edited data).
@login_required # Ensures only logged-in users can access this URL.
def edit(id: int): # This function handles the editing of a specific signal based on its ID.
    task = MyTask.query.get_or_404(id) # Retrieves the 'MyTask' object with the given 'id' from the database, or returns a 404 error if not found.
    if task.user_id != current_user.id:  # Checks if the task belongs to the currently logged-in user.
        flash('Unauthorised action: You can only edit your own signals')  # Displays an error if the user tries to edit someone else's signal.
        return redirect(url_for('index')) # Redirects back to the main list.
    form = SignalForm(obj=task) # Creates an instance of the 'SignalForm' and pre-populates it with the existing data from the 'task' object. This makes it easy to display the current values in the edit form.
    if request.method == "POST": # Checks if the request method is POST, meaning the user has submitted the edit form.
        if form.validate_on_submit(): # Validates the submitted form data against the rules defined in 'SignalForm'.
            eta_str = form.eta.data.strip() # Gets the ETA data from the form and removes any extra whitespace.
            if eta_str: # Checks if the ETA string is not empty.
                try: # Tries to parse the ETA string into a datetime object to validate its format.
                    datetime.strptime(eta_str, '%d-%m-%Y')
                except ValueError:  # If the ETA format is invalid, this error is caught.
                    flash('Invalid ETA date (e.g., 32-01-2025 is not valid).', 'error') # Shows an error message to the user.
                    return render_template('edit.html', task=task, form=form) # Re-renders the edit form with the error.
            try: # Starts a 'try' block for database operations.
                task.signal_from = form.signal_from.data # Updates the 'signal_from' attribute of the 'task' object with the value from the form.
                task.commodity = form.commodity.data # Updates the 'commodity' attribute....
                task.departure = form.departure.data
                task.arrival_port = form.arrival_port.data
                task.eta = eta_str if eta_str else None # Updates the 'eta' attribute.
                db.session.commit() # Saves the changes made to the 'task' object in the database.
                flash('Signal updated successfully.', 'success') # Shows a success message.
                return redirect("/list") # Redirects the user back to the main list.
            except Exception as e:  # Catches any database errors.
                db.session.rollback() # Undoes any changes in the session.
                flash(f'Error: {str(e)}', 'error') # Displays an error message.
        return render_template('edit.html', task=task, form=form) # If the form submission was not valid, re-renders the edit form with validation errors.
    return render_template('edit.html', task=task, form=form)  # For a GET request (when the user first visits the edit page), this renders the 'edit.html' template, pre-filled with the 'task' data in the 'form'.

'''
#Only runs the code when Python file is executed directly
if __name__ == '__main__': # This is a standard Python construct that checks if the script is being run directly (not imported as a module).
    with app.app_context(): # Creates an application context. This is needed for certain operations like database interactions outside of a request context.
        db.create_all() # # Creates the database tables (defined by the SQLAlchemy models like 'User' and 'MyTask') in the database if they don't already exist.
    app.run(port=5001, debug=True) # Starts the Flask development web server. 'port=5001' specifies the port the server will listen on, and 'debug=True' enables debugging mode (which provides more helpful error messages and automatic reloading of the server when you make changes to the code). **Remember to set `debug=False` in a production environment.**