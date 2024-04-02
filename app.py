from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
from flask_cors import CORS
import json
import sqlite3
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo

from peewee import SqliteDatabase, Model, CharField,IntegrityError,IntegerField,DoesNotExist

app = Flask(__name__)

app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['MYSQL_HOST'] = ''
app.config['MYSQL_USER'] = 'bablumoze'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'your_database'

#mongodb+srv://bablumoze:<password>@cluster0.oq3mqne.mongodb.net/

mysql = MySQL(app)


login_manager = LoginManager(app)

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
    id = IntegerField(primary_key=True)
    firstname = CharField(max_length=50)
    lastname = CharField(max_length=50)
    email = CharField(max_length=100, unique=True)
    mobilenumber = CharField(max_length=15)
    password = CharField(max_length=100)

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

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
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

    if request.method == 'POST':


    return render_template('login.html')

def initialize():
    DATABASE.connect()
    DATABASE.create_tables([User], safe=True)
    DATABASE.close()

if __name__ == '__main__':
    initialize()
    app.run(host='0.0.0.0',port=5000, debug=True)