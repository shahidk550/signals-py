#This code treats the eta as a string.

from flask import Flask, render_template, redirect, request
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import re

#My app set up
app = Flask(__name__)
Scss(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)


#Data Class - Row of data
class MyTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    signal_from = db.Column(db.String(100), nullable=False)
    commodity = db.Column(db.String(100))
    departure = db.Column(db.String(100))
    arrival_port = db.Column(db.String(100))
    eta = db.Column(db.String(100))
    complete = db.Column(db.DateTime, nullable=True, default=None)
    created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"Task {self.id} - {self.signal_from}"

@app.route("/list", methods=["POST", "GET"])
def index():
    tasks = MyTask.query.order_by(MyTask.created).all()

    if request.method == "POST":
        signal_from = request.form['signal_from']
        commodity = request.form['commodity']
        departure = request.form['departure']
        arrival_port = request.form['arrival_port']
        eta_str = request.form['eta'].strip( ) 

        if not signal_from:
            return render_template('index.html', tasks=tasks, error="Signal From is required")
        
            # Optional: Validate ETA format
        if eta_str and not re.match(r'\d{2}-\d{2}-\d{4}', eta_str):
            return render_template('index.html', tasks=tasks, error="ETA must be in DD-MM-YYYY format (e.g., 04-05-2023).")
            
        try:
            eta = eta_str if eta_str else None
            print(f"ETA input: '{eta}'")  # Debug print
            new_task = MyTask(signal_from=signal_from, commodity=commodity, departure=departure, arrival_port=arrival_port, eta=eta, complete=None, created=datetime.utcnow())
            db.session.add(new_task)
            db.session.commit()
            return redirect("/list")
        except Exception as e:
            print(f"ERROR: {e}")
            return render_template('index.html', tasks=tasks, error=str(e))

    return render_template('index.html', tasks=tasks)


#Creates a route for delete function:
@app.route("/delete/<int:id>")
def delete(id):
    task_to_delete = MyTask.query.get_or_404(id)
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect("/list")
    except Exception as e:
        tasks = MyTask.query.order_by(MyTask.created).all()
        return render_template('index.html', tasks=tasks, error=str(e))

#create a route for edit function:
@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit(id:int):
    task = MyTask.query.get_or_404(id) #create a task and id and check if im sending or gettin info

    if request.method == "POST": #if I send info update content
        signal_from = request.form['signal_from'] #take the fields and get form and put in content
        commodity = request.form['commodity']
        departure = request.form['departure']
        arrival_port = request.form['arrival_port']
        eta_str = request.form['eta'].strip()

        if not signal_from:
            return render_template('edit.html', task=task, error="Signal From is required")
        
        #Validate ETA format
        if eta_str and not re.match(r'\d{2}-\d{2}-\d{4}', eta_str):
            return render_template('edit.html', task=task, error="ETA must be in DD-MM-YYYY format (e.g., 04-05-2023).")
        
        try:
           
           task.signal_from = signal_from
           task.commodity = commodity
           task.departure = departure
           task.arrival_port = arrival_port
           task.eta = eta_str if eta_str else None
           print(f"Updating task {id}: signal_from='{signal_from}', eta='{eta_str}'")  # Debug print
           db.session.commit()
           return redirect("/list")
          
        except Exception as e:
            print(f"Error:{e}")
    #Create a new page to allow user to edit the data  
            return render_template('edit.html',task=task, error=str(e))

# Handle GET request: render edit form with task's current values
    return render_template('edit.html', task=task)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=5001, debug=True)