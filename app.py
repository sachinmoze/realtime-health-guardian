from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_cors import CORS
import json
import sqlite3
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin,current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo

from peewee import SqliteDatabase, Model, CharField,IntegrityError,IntegerField,DoesNotExist,BooleanField,ForeignKeyField
from flask_mail import Mail, Message

import os
from dotenv import load_dotenv, dotenv_values 
load_dotenv() 

login_manager = LoginManager()

app = Flask(__name__)

login_manager.init_app(app)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

## Database configurations
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
mysql = MySQL(app)

MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_PORT = os.getenv('MAIL_PORT')
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
MAIL_USE_TLS = os.getenv('MAIL_USE_TLS')
MAIL_USE_SSL = os.getenv('MAIL_USE_SSL')

## Mail configurations
app.config['MAIL_SERVER']= MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_USE_TLS'] = eval(MAIL_USE_TLS)
app.config['MAIL_USE_SSL'] = eval(MAIL_USE_SSL)

mail = Mail(app)

#mongodb+srv://bablumoze:<password>@cluster0.oq3mqne.mongodb.net/




# conn = sqlite3.connect('health.db')
# cursor = conn.cursor()
# cursor.execute("""
#     CREATE TABLE IF NOT EXISTS users (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     firstname VARCHAR(50),
#     lastname VARCHAR(50),
#     email VARCHAR(100) UNIQUE,
#     mobilenumber VARCHAR(15),
#     password VARCHAR(100) NOT NULL
#         )
#     """)
# conn.commit()
# conn.close()

class SignupForm(FlaskForm):
    firstName = StringField('First Name', validators=[DataRequired()])
    lastName = StringField('Last Name')
    email = StringField('Email', validators=[DataRequired(), Email()])
    countryCode = StringField('Country Code', validators=[DataRequired()])
    mobile = StringField('Mobile Number', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirmPassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])


DATABASE = SqliteDatabase("health1.db")



class User(UserMixin,Model):
    #id = IntegerField(primary_key=True)
    firstname = CharField(max_length=50)
    lastname = CharField(max_length=50)
    email = CharField(max_length=100, unique=True)
    mobilenumber = CharField(max_length=15)
    password = CharField(max_length=100)
    authenticated_google_fit = BooleanField(default=False)

    class Meta:
        database = DATABASE

    @classmethod
    def user_exists(cls, email):
        try:
            user = cls.get(cls.email == email)
            return True
        except cls.DoesNotExist:
            return False

    @classmethod
    def create_user(cls, firstname, lastname, email, mobilenumber, password):
        try:
            hashed_password = generate_password_hash(password)
            user = cls.create(
                firstname=firstname,
                lastname=lastname,
                email=email,
                mobilenumber=mobilenumber,
                password=hashed_password
            )
            return user
        except Exception as e:
            raise Exception("Error creating user",e)
    
    def get_credentials(self):
        # Assuming you have a one-to-one relationship between User and UserCredentials
        # Replace 'UserCredentials' with the name of your UserCredentials model
        try:
            return self.user_google_fit_credentials
        except UserGoogleFitCredentials.DoesNotExist:
            return None

class UserGoogleFitCredentials(Model):
    token = CharField()
    refresh_token = CharField()
    token_uri = CharField()
    client_id = CharField()
    client_secret = CharField()
    scopes = CharField()
    user = ForeignKeyField(User, backref='user_google_fit_credentials')
    class Meta:
        database = DATABASE

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = SignupForm()

    if request.method == 'POST' and form.validate_on_submit():
        print('Form validated')
        # Process form data (e.g., save to database)
        firstname = request.form['firstName']
        lastname = request.form['lastName']
        email = request.form['email']
        countryCode = request.form['countryCode']
        mobile = request.form['mobile']
        password = request.form['password']
        #hashed_password = generate_password_hash(password)
        
        # conn = sqlite3.connect('health.db')
        # cursor = conn.cursor()
        # # cursor.execute("INSERT INTO users (firstname, lastname, email, mobilenumber, password) VALUES (%s, %s, %s, %s, %s)",
        # #             (firstname, lastname, email, countryCode + mobile, hashed_password))
        # cursor.execute("INSERT INTO users (firstname, lastname, email, mobilenumber, password) VALUES (?, ?, ?, ?, ?)",
        #                (firstname, lastname, email, countryCode+mobile, hashed_password))
        # conn.commit()
        # conn.close()
        
        if User.user_exists(email):
            flash('Email id already exists, Please sign up with new email or Log in.', 'danger')
            return redirect(url_for('signup'))
        else:
            user=User.create_user(firstname, lastname, email, countryCode+mobile, password)
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html', form=form)



@app.route('/onboarding')
def onboarding():
    return render_template('onboarding.html')


@app.route('/login', methods=['GET', 'POST'])
def login():

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
       
        if not User.user_exists(email):
            flash('Email id does not exist. Please sign up.', 'danger')
            return redirect(url_for('login'))

        user = User.get(User.email == email)
        
        if check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Password is incorrect. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


# @app.route('/resetpassword', methods=['GET', 'POST'])
# def resetpassword():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         if not User.user_exists(email):
#             flash('Email id does not exist. Please sign up.', 'danger')
#             return redirect(url_for('signup'))
#         else:
#             flash('Password reset link sent to your email, Follow the link to reset password', 'warning')
#             return redirect(url_for('login'))
#     return render_template('resetpassword.html')


@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    if request.method == 'POST':
        email = request.form.get('email')
        if not User.user_exists(email):
            flash('Email id does not exist. Please sign up.', 'danger')
            return redirect(url_for('signup'))
        else:
            flash('Password reset link sent to your email, Follow the link to reset password', 'warning')
            return redirect(url_for('login'))
    return render_template('forgotpassword.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))    

@app.route('/health-metrics')
@login_required
def health_metrics():
    return render_template('health-metrics.html')

@app.route('/emergency-contacts')
@login_required
def emergency_contacts():
    return render_template('emergency-form.html')

@app.route('/dashboard')
@login_required
def dashboard():
    print("in dashboard",current_user.authenticated_google_fit)
    return render_template('dashboard.html')

@app.route('/mail-test')
def mail_test():
    msg = Message(subject='Hello from flask app!', sender='healthguardian@mailtrap.io', recipients=['sachinmoze@gmail.com','sachin.moze@gmail.com'])
    msg.body = "Hey Sachin, sending you this email from my Flask app, just checking if it works"
    mail.send(msg)
    return "Message sent!"

@app.route('/google-fit')
def google_fit():
    if current_user.is_authenticated:
        
        #current_user.is_authenticated_google_fit = True
        #login_user(current_user)
        print(current_user)
        #user_id = current_user.user_id
        print(current_user.authenticated_google_fit)
        try:
            user = User.get(User.id == current_user.get_id())
            user.authenticated_google_fit = True
            user.save()
            load_user(user.id)
            print(current_user.authenticated_google_fit)
            return redirect(url_for('dashboard'))
        except DoesNotExist:
            # Handle the case where the user ID is not found in the database
            pass  
        return redirect(url_for('dashboard'))


# @property
# def is_authenticated_google(self):
#     return session.get('is_authenticated_google_fit', False)

def initialize():
    DATABASE.connect()
    DATABASE.create_tables([User], safe=True)
    DATABASE.close()

if __name__ == '__main__':
    initialize()
    app.run(host='0.0.0.0',port=5000, debug=True)