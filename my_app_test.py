from flask import Flask, render_template, redirect, request, flash, url_for, session, jsonify, current_app #Flask is the main tool to help build the website/app and also manage the pages, requests and flow of info.
from flask_scss import Scss #makes it easier to manage css
from flask_sqlalchemy import SQLAlchemy #Db to manage information 
from flask_wtf import FlaskForm #Helps to create and manage the forms on the website - text boxes, passwords, buttons etc
from wtforms import StringField, PasswordField, SubmitField #Rules for the forms
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp #Rules we can set for the forms 
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user #Helps to manage the logins, logouts and track who is using the site.
from sqlalchemy.sql import func #Access to db functions like sorting data 
import bcrypt #Tool to securely store the passwords and hash them
from datetime import datetime #Allows us to work with date and times
import re #Checking for patterns ie if ETA date looks like a date
import requests # Import the 'requests' library for making HTTP requests to external APIs.
import os 
import uuid
import logging
from dotenv import load_dotenv
import json # Import the jason module

# Load environment variables
load_dotenv()
log_filename = os.getenv('LOG_FILENAME')
print(log_filename)
# Configure logging
logging.basicConfig(level=logging.INFO, filename=log_filename, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# App setup
app = Flask(__name__) #Creates the web application 
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////Users/shahid.khan/dev/signals-py/database.db" #Tells the app where to find the db
#app.config['SQLALCHEMY_BINDS'] = {
 #   'api': os.getenv('SIGNALS_DB_URL', 'postgresql://shahidkhan@localhost/signals_admin')
#}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

app.config['SECRET_KEY'] = 'your-unique-secret-key-1234567890'  # Replace with your unique key!
app.config['SESSION_COOKIE_SECURE'] = False  # Disabled for local testing (no HTTPS), in real website turn to TRUE
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['API_MODE'] = os.getenv('API_MODE', 'external') # Default: external API
app.config['UI_MODE'] = os.getenv('UI_MODE', 'internal') # Default: internal (SQLite)

# Validate API_MODE at startup
valid_api_modes = ['external', 'mock']
if app.config['API_MODE'] not in valid_api_modes:
    logger.error(f"Invalid API_MODE: {app.config['API_MODE']}. Valid modes: {valid_api_modes}")
    raise ValueError(f"Invalid API_MODE: {app.config['API_MODE']}")

# Warn if SESSION_COOKIE_SECURE is False in production
if not app.debug and not app.config['SESSION_COOKIE_SECURE']:
    logger.warning("SESSION_COOKIE_SECURE is False in production. Enable for HTTPS.")


Scss(app, static_dir='static', asset_dir='static') #App will use Scss for styling CSS

db = SQLAlchemy(app) #Connects the app to the db using Flask-SQLAlchemy



# User model - represents the user in the table of db
class User(db.Model, UserMixin): #Blueprint for how we store the data - each user will have id, email. pw, provider and role (i.e admin). Inherits 'db.Model and 'UserMixin' (from Flask-Login, providing default implementations for user properties).
    __bind_key = None
    id = db.Column(db.Integer, primary_key=True) 
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)  # Stores hashed password
    provider = db.Column(db.String(20), nullable=True)  # For future OAuth (e.g., 'google', 'github')
    role = db.Column(db.String(10), nullable=False, default='user')  # 'user' or 'admin'

# API User model (currently PostgreSQL for API)
class APIUser(db.Model):
    __bind_key = 'api'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    api_user_id = db.Column(db.String(255), unique=True)

    def __repr__(self):
        return f'<APIUser {self.email}>'


# Data Class - Determines the rows of data in the db
class MyTask(db.Model): # Defines a Python class named 'MyTask' that represents the 'mytask' table in database.
    __bind_key__ = None
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

# Creates the Forms
class SignalForm(FlaskForm): # Defines a form for creating or editing 'MyTask' objects. It inherits from 'FlaskForm'.
    signal_from = StringField('Signal From', validators=[DataRequired(), Length(max=100)]) #A text field for the signal source, requires data and can be up to 100 characters.
    commodity = StringField('Commodity', validators=[Length(max=100)])
    departure = StringField('Departure', validators=[Length(max=100)])
    arrival_port = StringField('Arrival Port', validators=[Length(max=100)])
    eta = StringField('ETA (dd-mm-yyyy)', validators=[Length(max=100), Regexp(r'^\d{2}-\d{2}-\d{4}$|^$', message="ETA must be in DD-MM-YYYY format (e.g., 04-05-2023).")])
    submit = SubmitField('Submit') # A submit button for the form.

class RegisterForm(FlaskForm):# Defines a form for user registration.
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)]) # An email field, requires data, must be a valid email format, and can be up to 120 characters.
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])  # A password field, requires data and must be at least 8 characters long.
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')]) # A password confirmation field, requires data and must be equal to the value entered in the 'password' field.
    submit = SubmitField('Register') # A submit button for the registration form.

class LoginForm(FlaskForm): # Defines a form for user login.
    email = StringField('Email', validators=[DataRequired(), Email()]) 
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class APIRegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=11)])
    submit = SubmitField('Register via API')


# Initialize Flask-Login 
login_manager = LoginManager() #Sets up the login manager 
login_manager.init_app(app) #Connects the login manager to Flask app/site
login_manager.login_view = 'login' #Tells Flask-Login where to the send users if they need to login.

# Flask-Login user manager 
@login_manager.user_loader # A decorator that registers a function to load a user from the database based on their ID, which Flask-Login stores in the user's session.
def load_user(user_id):  # This function takes a user ID and should return the corresponding user object from the database
    from sqlachemy.orm import Session
    with db.sessions() as session:
        return User.query.get(int(user_id)) # Queries the 'User' table in the database for a user with the given ID and returns the user object.

#----------UI Routes-------------------------------------------------------

#Defines the web address (/register) for the registration page (Web UI Routes)
@app.route('/todo/register', methods=['GET', 'POST']) # Decorator that links the URL '/register' to the 'register' function. It handles both GET requests (when a user visits the page) and POST requests (when the user submits the registration form).
def register(): #Handles the showing and processing form when user submits it.
    if current_user.is_authenticated: # Checks if the current user is already logged in. 'current_user' is provided by Flask-Login.
        return redirect(url_for('index')) # If logged in, redirects the user to the main page (route named 'index').
    form = RegisterForm() # Creates an instance of the 'RegisterForm'.
    logger.info(f"UI register - Request method: {request.method}, Form data: {request.form}, Session CSRF: {session.get('csrf_token', 'No CSRF token in session')}") 
    if form.validate_on_submit(): # Checks if the registration form has been submitted (POST request) and if all the validators in the form have passed.
        logger.info(f"UI register - Form validated successfully") # Prints a success message if the form is valid.
        ui_mode = current_app.config['UI_MODE']
        logger.info(f"UI register - UI_MODE: {ui_mode}")
        if ui_mode in ('internal', 'sqlite'):
        # Check if email exists
            if User.query.filter_by(email=form.email.data).first(): # Queries the 'User' table to see if a user with the entered email already exists. '.first()' returns the first matching user or None.
                flash('Email already taken.', 'error') # If the email exists, it displays an error message to the user using Flask's 'flash' system.
                logger.warning(f"UI register - Email already taken: {form.email.data}")
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
                logger.info(f"UI register - User registered: {form.email.data} redirecting to login") # Prints a log message.
                return redirect(url_for('login')) # Redirects the user to the login page.
            except Exception as e: # Catches any exceptions (errors) that might occur during database operations.
                db.session.rollback() # If an error occurred, it rolls back the database session to its previous state, preventing partial saves.
                flash(f'Error: {str(e)}', 'error') # Displays a generic error message to the user.
                logger.error(f"UI register - Database error: {str(e)}") # Prints the specific database error to the console for debugging.
                return render_template('register.html', form=form) # Re-renders the registration form with the error message.
        elif ui_mode == 'mock':
            flash('Registration successful! Please log in.', 'success')
            logger.info(f"UI register - Mock registration: {form.email.data}, redirecting to login")
            return redirect(url_for('login'))

        else:
            flash(f'Invalid UI_MODE: {ui_mode}', 'error')
            logger.error(f"UI register - Invalid UI_MODE: {ui_mode}")
            return render_template('register.html', form=form)

    else: # If the form validation fails (e.g., passwords don't match, email is invalid).
        logger.warning(f"UI register - Form validation failed: {form.errors}") # Prints a log message indicating validation failure.
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
            logger.info(f"Login - User logged in: {form.email.data}")
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
        tasks = MyTask.query.filter_by(user_id=current_user.id).order_by(MyTask.eta.asc().nullslast()).all() #Get the data/signals from table named Mytask but only of those matching user_id and sort them by eta, ascending (asc) order including those with no ETA
    logger.info(f"Index - User: {current_user.email}, Role: {current_user.role}, ID: {current_user.id}, Tasks: {[f'Task {task.id} - {task.signal_from} (User ID: {task.user_id})' for task in tasks]}")
    if request.method == "POST": # Checks if the request method is POST (meaning a form has been submitted).
        logger.info(f"Index - POST form data: {request.form}") # Prints the data from the submitted form for debugging.
        if form.validate_on_submit(): # Checks if the submitted form data is valid according to the validators defined in the 'SignalForm' class.
            eta_str = form.eta.data.strip() # Gets the ETA data from the form and removes any leading or trailing whitespace.
            if eta_str: # Checks if the ETA string is not empty.
                try: # Starts a 'try' block to handle potential errors when converting the ETA string to a datetime object.
                    datetime.strptime(eta_str, '%d-%m-%Y') # Attempts to convert the ETA string into a datetime object based on the 'dd-mm-yyyy' format. If the format is incorrect, it will raise a ValueError.
                except ValueError: # Catches the ValueError if the ETA string is not in the expected format.
                    flash('Invalid ETA date (e.g., 32-01-2025 is not valid).', 'error') # Displays an error message to the user.
                    logger.warning("Index - Invalid ETA date") # Prints a log message indicating ETA validation failure.
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
                logger.info(f"Index - Signal created: {new_task.__repr__()}") # Prints a message to the console 
                return redirect("/list") # Sends the user's browser to the '/list' URL
            except Exception as e: #This starts a block of code that will handle any errors that might occur in the 'try' block above (e.g., issues with the database). 'e' will contain information about the error.
                db.session.rollback() # If an error occurred, this line undoes any changes that were attempted in the database session
                flash(f'Error: {str(e)}', 'error') # Displays an error message to the user, including the specific error that occurred. 'error' is another category for the message, usually styled to indicate a problem.
                logger.error(f"Index - Database error: {str(e)}") # Prints the specific database error to the console for debugging.
        else: # This 'else' block runs if the `if form.validate_on_submit():` condition was false, meaning the submitted form data was not valid according to the rules set.
            logger.warning(f"Index - Form validation failed: {form.errors}") # Prints the specific validation errors to the console
        return render_template('index.html', tasks=tasks, form=form) # Regardless of whether the form was submitted or if it was invalid, this line renders the 'index.html' template, passing the list of tasks and the form object to it so they can be displayed on the webpage.
    return render_template('index.html', tasks=tasks, form=form) # This line is reached if the request method was GET (the user just visited the '/list' page), and it renders the 'index.html' template to display the initial list of tasks and the empty form for adding new signals.

#Allows logged in users to delete their own signals 
@app.route("/todo/delete/<int:id>") # This decorator defines a new URL route '/delete/<int:id>'. When a user visits a URL like '/delete/123', the 'delete' function will be executed, and 'id' will be the number in the URL (e.g., 123). '<int:id>' specifies that 'id' should be treated as an integer.
@login_required # Ensures that only logged-in users can access this URL.
def delete(id): # This function handles the deletion of a specific signal based on its ID.
    task = MyTask.query.get_or_404(id) # This line tries to find a 'MyTask' object in the database with the given 'id'. If a task with that ID is found, it's stored in the 'task' variable. If no task is found, it automatically returns a 404 (Not Found) error to the user.
    if task.user_id != current_user.id:  # This checks if the 'user_id' of the task (the user who created it) is different from the ID of the currently logged-in user.
        flash('Unauthorized action: You can only delete your own signal', 'error') # If the task doesn't belong to the current user, it displays an error message.
        logger.warning(f"Delete - Unauthorised: User {current_user.id} attempted to delete task {id}")
        return redirect(url_for('index')) # And then redirects the user back to the main list of signals.
    try: # Starts a 'try' block to handle potential database errors during deletion.
        db.session.delete(task)  # This marks the 'task' object for deletion in the database session.
        db.session.commit() # This line actually executes the deletion in the database.
        flash('Signal deleted successfully.', 'success') # Displays a success message to the user.
        logger.info(f'Delete - Task {id} deleted by user {current_user.id}')
        return redirect("/list") # Redirects the user back to the list of signals, which should now be updated.
    except Exception as e: # Catches any errors that might occur during the database operations.
        db.session.rollback()  # If an error occurred, this line undoes any changes in the session.
        flash(f'Error: {str(e)}', 'error') # Displays an error message to the user.
        logger.error(f"Delete - Database error {str(e)}")
        return redirect("/list")

#Allows logged in users to edit their own signals and updates existing data and database. 
@app.route("/todo/edit/<int:id>", methods=["GET", "POST"]) # This decorator defines a URL route '/edit/<int:id>' that handles both GET requests (to display the edit form) and POST requests (to submit the edited data).
@login_required # Ensures only logged-in users can access this URL.
def edit(id: int): # This function handles the editing of a specific signal based on its ID.
    task = MyTask.query.get_or_404(id) # Retrieves the 'MyTask' object with the given 'id' from the database, or returns a 404 error if not found.
    if current_user.role != 'admin' and task.user_id != current_user.id:  # Checks if user is authorised (admins can edit all signals).
        flash('Unauthorized action: You can only edit your own signals')  # Displays an error if the user tries to edit someone else's signal.
        logger.warning(f"Edit - Unauthorized: User {current_user.id} attempted to edit task {id}")
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
                    logger.warning(f"Edit - Invalid ETA date for task {id}")
                    return render_template('edit.html', task=task, form=form) # Re-renders the edit form with the error.
            try: # Starts a 'try' block for database operations.
                task.signal_from = form.signal_from.data # Updates the 'signal_from' attribute of the 'task' object with the value from the form.
                task.commodity = form.commodity.data # Updates the 'commodity' attribute....
                task.departure = form.departure.data
                task.arrival_port = form.arrival_port.data
                task.eta = eta_str if eta_str else None # Updates the 'eta' attribute.
                db.session.commit() # Saves the changes made to the 'task' object in the database.
                flash('Signal updated successfully.', 'success') # Shows a success message.
                logger.info(f"Edit - Task {id} updated by user {current_user.id}")
                return redirect("/list") # Redirects the user back to the main list.
            except Exception as e:  # Catches any database errors.
                db.session.rollback() # Undoes any changes in the session.
                flash(f'Error: {str(e)}', 'error') # Displays an error message.
                logger.error(f"Edit - Database error: {str(e)}")
        return render_template('edit.html', task=task, form=form) # If the form submission was not valid, re-renders the edit form with validation errors.
    return render_template('edit.html', task=task, form=form)  # For a GET request (when the user first visits the edit page), this renders the 'edit.html' template, pre-filled with the 'task' data in the 'form'.

#------------API Routes--------------------------------------------


@app.route('/todo/api/register_form', methods=['GET', 'POST'])
def api_register_form():
    form = APIRegisterForm()
    if form.validate_on_submit():
        logger.info(f"API register_form - Form validated, email: {form.email.data}")
        payload = {
            'email': form.email.data,
            'password': form.password.data
        }
        headers = {
            'Content-Type': 'application/json'
        }
        try:
            logger.info(f"API register_form - Posting to URL: {url_for('api_register', _external=True)}") 
            response = requests.post(
                url_for('api_register', _external=True),
                json=payload,
                headers=headers,
                timeout=10
            )
            logger.info(f"API register_form - Response status: {response.status_code}, headers: {response.headers}, body: {response.text}")
            if response.status_code == 200:
                if response.headers.get('Content-Type', '').startswith('application/json'):
                    try:
                        response_json = response.json()
                        logger.info(f"API register_form - Parsed JSON: {response_json}")
                        flash('Registration successful! You can log in once available.', 'success')
                        logger.info("API register_form - Registration successful, redirecting to login")
                        return redirect(url_for('login'))
                    
                    except ValueError:
                        flash('Registration failed: Invalid JSON response from API.', 'error')
                        logger.warning(f"API register_form - Invalid JSON response from API: {response.text}")
                else:
                    flash('Registration failed: Non-JSON response from API.', 'error')
                    logger.warning(f"API register_form - Non-JSON response. Content-Type: {response.headers.get('Content-Type', 'unknown')}, Body: {response.text}")
                return render_template('api_register.html', form=form)
                
            else:
                try:
                    response_json = response.json()
                    error_message = response_json.get('error', 'Unknown error')
                    error_code = response_json.get('error_code', 'unknown')
                    if response.status_code == 400:
                        user_message = 'Invalid email or password format. Please check your input.'
                    elif response.status_code == 409:
                        user_message = 'This email is already registered. Please try another.'
                    else:
                        user_message = f'Registration failed: {error_message}'
                    flash(user_message, 'error')
                    logger.warning(f"API register_form - Registration failed: {error_message}, code: {error_code}")
                except ValueError:
                    flash('Registration failed: Invalid response from API.', 'error')
                    logger.warning(f"API register_form - Invalid response from API: {response.text}")
                return render_template('api_register.html', form=form)    
        except requests.exceptions.Timeout:
            flash('Registration failed: API request timed out.', 'error')
            logger.error("API register_form - Request timed out")
            return render_template('api_register.html', form=form)
        except requests.exceptions.ConnectionError:
            flash('Registration failed: Unable to connect to API.', 'error')
            logger.error("API register_form - Connection error")
            return render_template('api_register.html', form=form)
        except requests.exceptions.RequestException as e:
            flash('Registration failed: An error occurred. Please try again.', 'error')
            logger.error(f"API register_form - Request error: {str(e)}")
            return render_template('api_register.html', form=form)
    else:
        logger.warning(f"API register_form - Form validation failed: {form.errors}")
    logger.info("API register_form - Rendering form")
    return render_template('api_register.html', form=form)

@app.route('/todo/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        logger.warning("API register - Missing email or password")
        return jsonify({'error': 'Missing email or password', 'error_code': 'missing_data'}), 400

    email = data['email']
    password = data['password']

    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        logger.warning(f"API register - Invalid email format: {email}")
        return jsonify({'error': 'Invalid email format', 'error_code': 'invalid_email'}), 400

    # Validate password
    if len(password) < 11:
        logger.warning(f"API register - Password too short: {len(password)} chars")
        return jsonify({'error': 'Password must be 11 characters long', 'error_code': 'password_too_short'}), 400

    api_mode = current_app.config['API_MODE']
    logger.info(f"API register - API_MODE: {api_mode}, email: {email}")
    if api_mode == 'external':
        existing_api_user = APIUser.query.filter_by(email=email).first()
        if existing_api_user:
            logger.warning(f"API register - Email already taken: {email}")
            return jsonify({'error': 'Email already taken in API database', 'error_code': 'user_already_exists'}), 409

        registration_data = {
            "email": email,
            "password": password
        }

        try:
            api_url = 'http://localhost:8080/auth/register'
            headers = {
                'Content-Type': 'application/json',
            }
            response = requests.post(api_url, json=registration_data, headers=headers, timeout=10)
            logger.info(f"API register - External API response status: {response.status_code}, headers: {response.headers}, body: {response.text!r}")

            # Initialize response_json as a dictionary
            response_json = {'id': str(uuid.uuid4()), 'resource_url': ''}

            if response.status_code in (400, 409, 500):
                try:
                    response_json = response.json()
                    logger.warning(f"API register - External API error: {response_json.get('message', 'API error')}")
                    return jsonify({
                        'error': response_json.get('message', 'API error'),
                        'error_code': response_json.get('error_code', 'unknown')
                    }), response.status_code
                except ValueError:
                    logger.warning(f"API register - External API invalid response: {response.text!r}")
                    return jsonify({
                        'error': 'Invalid response from external API',
                        'error_code': 'invalid_response'
                    }), response.status_code

            if response.status_code not in (200, 201):
                logger.warning(f"API register - Unexpected status code: {response.status_code}, body: {response.text!r}")
                return jsonify({
                    'error': 'Unexpected response from external API',
                    'error_code': 'unexpected_response'
                }), response.status_code

            # Handle success (200 or 201)
            logger.info(f"API register - Success status code: {response.status_code}, treating as successful registration")
            content_type = response.headers.get('Content-Type', '').lower()
            if 'application/json' in content_type and response.text.strip():
                try:
                    response_json = response.json()
                    if not isinstance(response_json, dict):
                        logger.warning(f"API register - JSON response is not a dictionary: {response_json!r}")
                        response_json = {'id': str(uuid.uuid4()), 'resource_url': ''}
                    else:
                        logger.info(f"API register - Parsed JSON response: {response_json}")
                except ValueError:
                    logger.warning(f"API register - Failed to parse JSON response: {response.text!r}")
                    response_json = {'id': str(uuid.uuid4()), 'resource_url': ''}
            else:
                logger.info(f"API register - Non-JSON or empty response, using generated ID. Content-Type: {content_type}, body: {response.text!r}")
                response_json = {'id': str(uuid.uuid4()), 'resource_url': ''}

            # Verify response_json is a dictionary
            if not isinstance(response_json, dict):
                logger.error(f"API register - response_json is not a dictionary: {response_json!r}")
                response_json = {'id': str(uuid.uuid4()), 'resource_url': ''}

            api_user_id = response_json.get('id', str(uuid.uuid4()))
            resource_url = response_json.get('resource_url', '')

            try:
                new_api_user = APIUser(email=email, api_user_id=api_user_id)
                db.session.add(new_api_user)
                db.session.commit()
                logger.info(f"API register - User stored in PostgreSQL, api_user_id: {api_user_id}")
            except Exception as e:
                db.session.rollback()
                logger.error(f"API register - Database error: {str(e)}")
                return jsonify({'error': f'Error storing user data in PostgreSQL: {str(e)}', 'error_code': 'database_error'}), 500

            logger.info(f"API register - Success, api_user_id: {api_user_id}")
            response = jsonify({
                'message': 'User registered successfully',
                'api_user_id': api_user_id,
                'email': email,
                'resource_url': resource_url
            })
            response.headers['Content-Type'] = 'application/json'
            return response, 200

        except requests.exceptions.RequestException as e:
            logger.error(f"API register - Connection error: {str(e)}")
            return jsonify({'error': f'Failed to connect to external API: {str(e)}', 'error_code': 'connection_error'}), 500
    elif api_mode == 'mock':
        api_user_id = str(uuid.uuid4())
        logger.info(f"API register - Mock registration, api_user_id: {api_user_id}")
        response = jsonify({
            'message': 'User registered successfully',
            'api_user_id': api_user_id,
            'email': email,
            'resource_url': ''
        })
        response.headers['Content-Type'] = 'application/json'
        return response, 200
    else:
        logger.error(f"API register - Invalid API_MODE: {api_mode}")
        return jsonify({'error': f'Invalid API_MODE: {api_mode}', 'error_code': 'invalid_mode'}), 400


#Only runs the code when Python file is executed directly
if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {str(e)}")
            raise
    app.run(port=5001, debug=True)