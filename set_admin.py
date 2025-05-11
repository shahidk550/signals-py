#Scripts sets the admin 

from my_app_test import app, db, User

email = 'shahidk550@gmail.com'

with app.app_context():
    user = User.query.filter_by(email=email).first()
    if user:
        user.role = 'admin'
        db.session.commit()
        print(f"User {user.email} set to admin")
    else:
        print(f"User with email {email} not found")