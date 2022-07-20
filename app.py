from flask import Flask, render_template, url_for, redirect,request,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import datetime
import sqlite3
import matplotlib.pyplot as plt
from matplotlib import style
from dateutil import parser

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    tracker = db.relationship('Tracker')
    log = db.relationship('Log')

class Tracker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    description = db.Column(db.String(150))
    tracker_type = db.Column(db.String(150))
    log = db.relationship('Log')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(150))
    value = db.Column(db.Integer)
    notes = db.Column(db.String(150))
    tracker_id = db.Column(db.Integer, db.ForeignKey('tracker.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    added_date_time = db.Column(db.String(150))


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    tracker = Tracker.query.all()
    return render_template('dashboard.html',user=current_user, tracker=tracker)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/add_tracker', methods = ['GET', 'POST'])
@login_required
def add_tracker():
    try:
        if request.method == 'POST':
            tracker_name = request.form.get('name')
            tracker_description = request.form.get('description')
            tracker_type = request.form.get('type')
            current_user_id = current_user.id
            tracker = Tracker.query.filter_by(name=tracker_name).first()
            if tracker and current_user_id == tracker.user_id:
                flash('The tracker "' + tracker_name + '" is already added by you.', category='error')
                return redirect(url_for('dashboard'))
            else:
                new_tracker = Tracker(name=tracker_name, description=tracker_description, tracker_type=tracker_type, user_id=current_user_id)
                db.session.add(new_tracker)
                db.session.commit()
                flash('New Tracker Added.', category='success')
                return redirect(url_for('dashboard'))
    except Exception as e:
        print(e)
        flash('Something went wrong.', category='error')
    return render_template("add_tracker.html", user=current_user)

@app.route('/delete_tracker/<int:recordid>', methods = ['GET', 'POST'])
@login_required
def delete_tracker(recordid):
    try:
        Tracker_details = Tracker.query.get(recordid)
        Tracker_name = Tracker_details.name
        db.session.delete(Tracker_details)
        db.session.commit()
        flash(Tracker_name + ' Tracker Removed Successfully.', category='success')
    except Exception as e:
        print(e)
        flash('Something went wrong.', category='error')
    return redirect(url_for('dashboard'))

@app.route('/edit_tracker/<int:recordid>', methods = ['GET' , 'POST'])
@login_required
def edit_tracker(recordid):
    this_tracker = Tracker.query.get(recordid)
    this_tracker_name = this_tracker.name
    try:
        if request.method == 'POST':
            tracker_name = request.form.get('name')
            tracker_description = request.form.get('description')
            tracker_type = request.form.get('type')
            current_user_id = current_user.id
            tracker = Tracker.query.filter_by(name=tracker_name).first()
            if tracker and tracker.user_id == current_user_id and this_tracker_name != tracker_name:
                flash('The tracker "' + tracker_name + '" is already added by you, Try a new name for your tracker.',
                      category='error')
            else:
                this_tracker.name = tracker_name
                this_tracker.description = tracker_description
                this_tracker.tracker_type = tracker_type
                db.session.commit()
                flash('Tracker Updated Successfully.', category='success')
                return redirect(url_for('dashboard'))
    except Exception as e:
        print(e)
        flash('Something went wrong.', category='error')
    return render_template("edit_tracker.html", user=current_user, tracker=this_tracker)



@app.route('/add_log/<int:recordid>', methods =['GET','POST'])
@login_required
def add_log(recordid):
    this_tracker = Tracker.query.get(recordid)
    now = datetime.datetime.now()
    try:
        if request.method == 'POST':
            log_date = request.form.get('date')
            log_value = request.form.get('value')
            log_notes = request.form.get('notes')
            new_log = Log(timestamp=log_date, value=log_value, notes=log_notes, tracker_id=recordid, user_id=current_user.id,
                          added_date_time=now)
            db.session.add(new_log)
            db.session.commit()
            flash('New Log Added For ' + this_tracker.name + ' Tracker', category='success')
            return redirect(url_for('dashboard'))
    except Exception as e:
        print(e)
        flash('Something went wrong.', category='error')
    return render_template("add_log.html", user=current_user, tracker=this_tracker, now =now)

@app.route('/delete_log/<int:recordid>', methods = ['GET','POST'])
@login_required
def delete_log(recordid):
    Log_details = Log.query.get(recordid)
    tracker_id = Log_details.tracker_id
    try:
        db.session.delete(Log_details)
        db.session.commit()
        flash('Log Removed Successfully.', category='success')
    except Exception as e:
        print(e)
        flash('Something went wrong.', category='error')
    return redirect(url_for('view_tracker', recordid=tracker_id))

@app.route('/edit_log/<int:recordid>', methods = ['GET', 'POST'])
@login_required
def edit_log(recordid):
    this_log = Log.query.get(recordid)
    this_tracker = Tracker.query.get(this_log.tracker_id)
    try:
        if request.method == 'POST':
            log_date = request.form.get('date')
            log_value = request.form.get('value')
            log_notes = request.form.get('notes')

            this_log.timestamp = log_date
            this_log.value = log_value
            this_log.notes = log_notes

            db.session.commit()
            flash(this_tracker.name + ' Log Updated Successfully.', category='success')
            return redirect(url_for('view_tracker', recordid=this_log.tracker_id))
    except Exception as e:
        print(e)
        flash('Something went wrong.', category='error')

    return render_template("edit_log.html", user=current_user, tracker=this_tracker, log=this_log)

@app.route('/view_tracker_log_graph/<int:recordid>', methods = ['GET', 'POST'])
@login_required
def view_tracker(recordid):
    now = datetime.datetime.now()
    selected_tracker = Tracker.query.get(recordid)
    logs = Log.query.all()
    try:
        conn = sqlite3.connect('database.db')
        print('Database connected successfully')
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, value FROM Log WHERE user_id = {} AND tracker_id = {}'.format(current_user.id,selected_tracker.id))
        graph_data = cursor.fetchall()
        dates_x = []
        values_y = []
        for row in graph_data:
            dates_x.append(parser.parse(row[0]))
            values_y.append(row[1])
        
        style.use('classic')
        
        fig = plt.figure(figsize=(12, 8))
        plt.plot_date(dates_x, values_y,'-')
        plt.xlabel('Date')
        plt.ylabel('Values')
        plt.tight_layout()
        plt.savefig('static/Images/graph.png')
        return render_template("view_tracker_log_graph.html", user=current_user, tracker=selected_tracker,
                               logs=logs)

    except Exception as e:
        print(e)
        flash('Some error occured.', category='error')
        return render_template("view_tracker_log_graph.html", user=current_user, tracker=selected_tracker,
                               logs=logs)



if __name__ == "__main__":
    app.run(debug=True)

