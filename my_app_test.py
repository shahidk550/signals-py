from flask import Flask, render_template, redirect, request, flash, url_for, session
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy.sql import func
import bcrypt
from datetime import datetime
import re

# App setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SECRET_KEY'] = 'your-unique-secret-key-1234567890'  # Replace with your unique key
app.config['SESSION_COOKIE_SECURE'] = False  # Disable for local testing (no HTTPS)
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
Scss(app)
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)  # Stores hashed password
    provider = db.Column(db.String(20), nullable=True)  # For future OAuth (e.g., 'google', 'github')
    role = db.Column(db.String(10), nullable=False, default='user')  # 'user' or 'admin'

# Data Class - Row of data
class MyTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    signal_from = db.Column(db.String(100), nullable=False)
    commodity = db.Column(db.String(100))
    departure = db.Column(db.String(100))
    arrival_port = db.Column(db.String(100))
    eta = db.Column(db.String(100))
    complete = db.Column(db.DateTime, nullable=True, default=None)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='tasks')

    def __repr__(self) -> str:
        return f"Task {self.id} - {self.signal_from}"

# Forms
class SignalForm(FlaskForm):
    signal_from = StringField('Signal From', validators=[DataRequired(), Length(max=100)])
    commodity = StringField('Commodity', validators=[Length(max=100)])
    departure = StringField('Departure', validators=[Length(max=100)])
    arrival_port = StringField('Arrival Port', validators=[Length(max=100)])
    eta = StringField('ETA (dd-mm-yyyy)', validators=[Length(max=100), Regexp(r'^\d{2}-\d{2}-\d{4}$|^$', message="ETA must be in DD-MM-YYYY format (e.g., 04-05-2023).")])
    submit = SubmitField('Submit')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    print(f"Request method: {request.method}")
    print(f"Form data: {request.form}")
    print(f"Session data: {session.get('csrf_token', 'No CSRF token in session')}")
    if form.validate_on_submit():
        print("Form validated successfully")
        # Check if email exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already taken.', 'error')
            return render_template('register.html', form=form)
        # Hash password
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        user = User(
            email=form.email.data,
            password=hashed_password.decode('utf-8'),
            provider='local',  # Default for password registration
            role='user'  # All new users are regular users
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            print("User registered, redirecting to login")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
            print(f"Database error: {str(e)}")
            return render_template('register.html', form=form)
    else:
        print("Form validation failed")
        print(f"Form errors: {form.errors}")
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route("/list", methods=["POST", "GET"])
@login_required
def index():
    form = SignalForm()
    if current_user.role == 'admin':
        tasks = MyTask.query.order_by(MyTask.eta.asc().nullslast()).all()
    else:
        tasks = MyTask.query.filter_by(user_id=current_user.id).order_by(MyTask.eta.asc().nullslast()).all()
    print(f"Current user: {current_user.email}, Role: {current_user.role}, ID: {current_user.id}")
    print(f"Retrieved tasks: {[f'Task {task.id} - {task.signal_from} (User ID: {task.user_id})' for task in tasks]}")
    if request.method == "POST":
        print(f"POST form data: {request.form}")
        if form.validate_on_submit():
            eta_str = form.eta.data.strip()
            if eta_str:
                try:
                    datetime.strptime(eta_str, '%d-%m-%Y')
                except ValueError:
                    flash('Invalid ETA date (e.g., 32-01-2025 is not valid).', 'error')
                    print("ETA validation failed")
                    return render_template('index.html', tasks=tasks, form=form)
            try:
                new_task = MyTask(
                    signal_from=form.signal_from.data,
                    commodity=form.commodity.data,
                    departure=form.departure.data,
                    arrival_port=form.arrival_port.data,
                    eta=eta_str if eta_str else None,
                    complete=None,
                    created=datetime.utcnow(),
                    user_id=current_user.id
                )
                db.session.add(new_task)
                db.session.commit()
                flash('Signal added successfully.', 'success')
                print(f"Signal created: {new_task.__repr__()}")
                return redirect("/list")
            except Exception as e:
                db.session.rollback()
                flash(f'Error: {str(e)}', 'error')
                print(f"Database error: {str(e)}")
        else:
            print(f"Form validation failed: {form.errors}")
        return render_template('index.html', tasks=tasks, form=form)
    return render_template('index.html', tasks=tasks, form=form)

@app.route("/delete/<int:id>")
@login_required
def delete(id):
    task = MyTask.query.get_or_404(id)
    if task.user_id != current_user.id:
        flash('Unauthorised action: You can only delete your own signal')
        return redirect(url_for('index'))
    try:
        db.session.delete(task)
        db.session.commit()
        flash('Signal deleted successfully.', 'success')
        return redirect("/list")
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
        tasks = MyTask.query.filter_by(user_id=current_user.id).order_by(MyTask.eta.asc().nullslast()).all()
        return render_template('index.html', tasks=tasks, form=SignalForm())

@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit(id: int):
    task = MyTask.query.get_or_404(id) 
    if task.user_id != current_user.id: 
        flash('Unauthorised action: You can only edit your own signals')
        return redirect(url_for('index'))
    form = SignalForm(obj=task)
    if request.method == "POST":
        if form.validate_on_submit():
            eta_str = form.eta.data.strip()
            if eta_str:
                try:
                    datetime.strptime(eta_str, '%d-%m-%Y')
                except ValueError:
                    flash('Invalid ETA date (e.g., 32-01-2025 is not valid).', 'error')
                    return render_template('edit.html', task=task, form=form)
            try:
                task.signal_from = form.signal_from.data
                task.commodity = form.commodity.data
                task.departure = form.departure.data
                task.arrival_port = form.arrival_port.data
                task.eta = eta_str if eta_str else None
                db.session.commit()
                flash('Signal updated successfully.', 'success')
                return redirect("/list")
            except Exception as e:
                db.session.rollback()
                flash(f'Error: {str(e)}', 'error')
        return render_template('edit.html', task=task, form=form)
    return render_template('edit.html', task=task, form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=5001, debug=True)