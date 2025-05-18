#DO NOT RUN - This code tries to use the eta as datetime but causes a value error in db - Run the my_app_test.py instead for now!

#imports 

from flask import Flask, render_template, redirect, request
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


#creates the app
app = Flask(__name__)
Scss(app)

# configure the SQLite database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

# Create the database
db = SQLAlchemy(app)


#create a class row of data - the model will generate the table row of data
class MyTask(db.Model): #No task can have the same ID - Model represents one signal
    id = db.Column(db.Integer, primary_key=True)
    signal_from = db.Column(db.String(100), nullable=False)
    commodity = db.Column(db.String(100))
    departure = db.Column(db.String(100))
    arrival_port = db.Column(db.String(100))
    eta = db.Column(db.DateTime, nullable=True)
   # content = db.Column(db.String(100), nullable=False)
    complete = db.Column(db.DateTime, default nullable=True, default=None)
    created = db.Column(db.DateTime, default=datetime.utcnow) #by order of creation

#The repr method provides a string represeantion instead of memory address
    def __repr__(self) -> str:
        return F"Task {self.id} - {self.signal_from}"


#route to homepage
@app.route("/list", methods=["POST", "GET"]) #Homepage can add and get data
def index():


    #1. Add signal - check action if we are sending or getting data
    if request.method =="POST": #if the action is send
       # current_task = request.form['content'] #get the information from the request form in html "form action" target 'content'

        signal_from = request.form['signal_from']
        commodity = request.form['commodity']
        departure = request.form['departure']
        arrival_port = request.form['arrival_port']
        eta_str = request.form['eta']

        #new_task = MyTask(signal_from=signal_from, commodity=commodity, departure=departure, arrival_port=arrival_port, eta=eta_str) #object of class model and give it 'content'

        try: #send the new task/signal to db
            print(f"Raw ETA input: '{eta_str}'")
            eta_dt = datetime.strptime(eta_str, '%d-%m-%Y') if eta_str else None
            print(f"Parsed ETA: {eta_dt}")
            new_task = MyTask(signal_from=signal_from, commodity=commodity, departure=departure, arrival_port=arrival_port, eta=eta_str) #object of class model and give it 'content'
            db.session.add(new_task)
            db.session.commit()

            return redirect("/list") #Go back to home page

        except Exception as e:
            print(f"ERROR:{e}")
            return f"ERROR: {e}"

    #else:# see all current signals
    task = MyTask.query.order_by(MyTask.created).all()
    return render_template('index.html', tasks=tasks)


    #2. See all signals


    return render_template("index.html")


if __name__=='__main__':


#Sets up the database
    with app.app_context():
        db.drop_all()
        db.create_all()


#runs the app
    app.run(port=5001, debug=True)
