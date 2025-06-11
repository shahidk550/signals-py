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
from datetime import datetime, timedelta #Allows us to work with date and times
import re #Checking for patterns ie if ETA date looks like a date
import requests 
import logging
from flask_wtf.csrf import CSRFProtect
import json 
import os 
from dotenv import load_dotenv
import urllib.parse
from datetime import datetime, timedelta, UTC

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

class SignalSearchForm(FlaskForm):  # Form for searching signals by date
    start_date = StringField('Start Date (YYYY-MM-DD)', [Length(max=100), Regexp(r'^\d{4}-\d{2}-\d{2}$|^$', message="Must be in YYYY-MM-DD format.")])
    end_date = StringField('End Date (YYYY-MM-DD)', validators=[Length(max=100), Regexp(r'^\d{4}-\d{2}-\d{2}$|^$', message="Must be in YYYY-MM-DD format.")])
    submit = SubmitField('Search Signals')

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

# Helper function to search signals
def search_signals(isn_slug, signal_type_slug, sem_ver, start_date=None, end_date=None, account_id=None):
    try:
        api_url = f"http://localhost:8080/api/isn/{isn_slug}/signal_types/{signal_type_slug}/v{sem_ver}/signals/search"
        headers = {
            "Authorization": f"Bearer {session['access_token']}",
            "Content-Type": "application/json"
        }
        params = {}
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date
        if account_id:
            params['account_id'] = account_id

        # Encode query parameters
        encoded_params = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        full_url = f"{api_url}?{encoded_params}" if params else api_url
        logger.info(f"API search_signals - Sending to URL: {full_url}")

        response = requests.get(full_url, headers=headers, timeout=10)
        return response

    except requests.exceptions.RequestException as e:
        logger.error(f"API search_signals - Connection error: {str(e)}")
        return None

#Routes 

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



@app.route('/api/dashboard', methods=['GET', 'POST'])
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

    return render_template('api_dashboard.html', email=session.get('email'), role=session.get('role'))



@app.route('/api/search_signal', methods=['GET', 'POST'])
def search_signal():
    if 'access_token' not in session: 
        flash('Please log in', 'error')
        return redirect(url_for('api_login'))


    search_form = SignalSearchForm()
    signals = []

    if search_form.validate_on_submit():
        start_date = search_form.start_date.data.strip() if search_form.start_date.data else None
        end_date = search_form.end_date.data.strip() if search_form.end_date.data else None
        # Extend end_date by 1 day to account for timezone (BST to UTC)
        if end_date:
            try:
                end_date_dt = datetime.strptime(end_date, '%Y-%m-%d')
                end_date = (end_date_dt + timedelta(days=1)).strftime('%Y-%m-%d')
            except ValueError:
                flash('Invalid end date format.', 'error')
                logger.warning(f"Invalid end_date format: {end_date}")
                return render_template('api_dashboard.html', email=session.get('email'), role=session.get('role'), submit_form=submit_form, search_form=search_form, signals=signals)
        account_id = session.get('account_id')



        response = search_signals(
            isn_slug='surrey-isn',
            signal_type_slug='test-signal',
            sem_ver='0.0.1',
            start_date=start_date,
            end_date=end_date,
            account_id=account_id
        )

        if response is None:
            flash('Failed to connect to API.', 'error')
        elif response.status_code == 200:
            signals = response.json()
            logger.info(f"API search_signals - Retrieved {len(signals)} signals")
        elif response.status_code == 401 and 'access_token_expired' in response.text.lower():
            if refresh_access_token():
                response = search_signals(
                    isn_slug='surrey-isn',
                    signal_type_slug='test-signal',
                    sem_ver='0.0.1',
                    start_date=start_date,
                    end_date=end_date,
                    account_id=account_id
                )
                if response and response.status_code == 200:
                    signals = response.json()
                    logger.info(f"API search_signals - Retrieved {len(signals)} signals after token refresh")
                else:
                    flash('Failed to fetch signals after token refresh.', 'error')
                    logger.warning(f"API search_signals - Failed after refresh: {response.text if response else 'No response'}")
            else:
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('api_login'))
        elif response.status_code == 400:
            flash('Invalid date format or parameters.', 'error')
            logger.warning(f"API search_signals - Bad request: {response.text}")
        else:
            flash('Failed to fetch signals: API error.', 'error')
            logger.warning(f"API search_signals - Failed: {response.text}")

    elif request.method == 'GET':
        # Default: Fetch signals for the last 30 days
        end_date = datetime.now(UTC).strftime('%Y-%m-%d')
        start_date = (datetime.now(UTC) - timedelta(days=30)).strftime('%Y-%m-%d')
        account_id = session.get('account_id')

        response = search_signals(
            isn_slug='surrey-isn',
            signal_type_slug='test-signal',
            sem_ver='0.0.1',
            start_date=start_date,
            end_date=end_date,
            account_id=account_id
        )

        if response and response.status_code == 200:
            signals = response.json()
            logger.info(f"API search_signals - Retrieved {len(signals)} signals on page load")
        elif response and response.status_code == 401 and 'access_token_expired' in response.text.lower():
            if refresh_access_token():
                response = search_signals(
                    isn_slug='surrey-isn',
                    signal_type_slug='test-signal',
                    sem_ver='0.0.1',
                    start_date=start_date,
                    end_date=end_date,
                    account_id=account_id
                )
                if response and response.status_code == 200:
                    signals = response.json()
                    logger.info(f"API search_signals - Retrieved {len(signals)} signals after token refresh on page load")
                else:
                    flash('Failed to fetch signals after token refresh.', 'error')
                    logger.warning(f"API search_signals - Failed after refresh on page load: {response.text if response else 'No response'}")
            else:
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('api_login'))
        elif response:
            flash('Failed to fetch signals: API error.', 'error')
            logger.warning(f"API search_signals - Failed on page load: {response.text}")

    return render_template('api_search_signal.html', email=session.get('email'), role=session.get('role'), search_form=search_form, signals=signals)



@app.route('/api/submit_signal', methods=['GET', 'POST'])
def submit_signal():
    logger.info('In API submit_signal function')
    if 'access_token' not in session:
        flash('Please log in to submit signals.', 'error')
        return redirect(url_for('api_login'))

    form = SignalSubmitForm()
    if request.method == 'POST' and form.validate_on_submit():
        logger.info(f"API submit_signal - Form validated, isn_slug: {form.isn_slug.data}")

        def send_signal_request():
            try:
                content = json.loads(form.content.data)
            except json.JSONDecodeError:
                flash('Invalid JSON format in content.', 'error')
                logger.warning('API submit_signal - Invalid JSON in content')
                return None
            signal = {
                "content": content,
                "local_ref": form.local_ref.data
            }
            if form.correlation_id.data:
                signal["correlation_id"] = form.correlation_id.data
            payload = {"signals": [signal]}
            api_url = f"http://localhost:8080/api/isn/{form.isn_slug.data}/signal_types/{form.signal_type_slug.data}/v{form.sem_ver.data}/signals"
            logger.info(f"API submit_signal - Sending to URL: {api_url}, Payload: {json.dumps(payload)}")
            headers = {
                "Authorization": f"Bearer {session['access_token']}",
                "Content-Type": "application/json"
            }
            response = requests.post(api_url, json=payload, headers=headers, timeout=10)
            return response

        response = send_signal_request()
        if response:
            logger.info(f"API submit_signal - Status: {response.status_code}, Body: {response.text}")
            if response.status_code == 401 and 'access_token_expired' in response.text.lower():
                if refresh_access_token():
                    response = send_signal_request()
                    if response:
                        logger.info(f"API submit_signal - Retry status: {response.status_code}, Body: {response.text}")
                    else:
                        flash('Failed to submit signal after token refresh.', 'error')
                        return render_template('api_submit_signal.html', email=session.get('email'), role=session.get('role'), submit_form=form)
                else:
                    flash('Session expired. Please log in again.', 'error')
                    return redirect(url_for('api_login'))
            if response.status_code == 201:
                data = response.json()
                flash(f"Signal submitted successfully! Stored signals: {len(data.get('stored_signals', []))}", 'success')
                logger.info(f"API submit_signal - Success for local_ref: {form.local_ref.data}")
                return redirect(url_for('api_dashboard'))
            elif response.status_code == 400:
                error_msg = response.json().get('error', 'Invalid request')
                if 'invalid_correlation_id' in response.text:
                    error_msg = 'Invalid correlation ID: must reference an existing signal of the same type.'
                flash(f"Submission failed: {error_msg}", 'error')
                logger.warning(f"API submit_signal - Bad request: {response.text}")
            elif response.status_code == 401:
                flash('Unauthorized: Invalid token or insufficient permissions.', 'error')
                logger.warning('API submit_signal - Unauthorized')
            elif response.status_code == 404:
                flash('Submission failed: ISN or signal type not found.', 'error')
                logger.warning(f"API submit_signal - Not found: {response.text}")
            else:
                flash('Submission failed: API server error.', 'error')
                logger.warning(f"API submit_signal - Failed: {response.text}")
        else:
            flash('Failed to connect to API.', 'error')
            logger.warning('API submit_signal - No response')

    elif request.method == 'POST':
        logger.debug(f"API submit_signal - Form validation failed: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {field}: {error}", 'error')

    return render_template('api_submit_signal.html', email=session.get('email'), role=session.get('role'), submit_form=form)

#Only runs the code when Python file is executed directly
if __name__ == '__main__': # This is a standard Python construct that checks if the script is being run directly (not imported as a module).
    with app.app_context(): # Creates an application context. This is needed for certain operations like database interactions outside of a request context.
        db.create_all() # # Creates the database tables (defined by the SQLAlchemy models like 'User' and 'MyTask') in the database if they don't already exist.
    app.run(port=5001, debug=True) # Starts the Flask development web server. 'port=5001' specifies the port the server will listen on, and 'debug=True' enables debugging mode (which provides more helpful error messages and automatic reloading of the server when you make changes to the code). **Remember to set `debug=False` in a production environment.**