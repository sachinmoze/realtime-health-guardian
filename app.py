from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from flask_mysqldb import MySQL
from flask_cors import CORS
import json
import sqlite3
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin,current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo

from peewee import SqliteDatabase, Model, CharField,IntegrityError,IntegerField,DoesNotExist,BooleanField,ForeignKeyField,DateTimeField,FloatField
from flask_mail import Mail, Message

import os
from dotenv import load_dotenv, dotenv_values 
load_dotenv() 

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from googleapiclient.discovery import build
import requests
CLIENT_SECRETS_FILE = "credentials.json"

SCOPES = [
          "https://www.googleapis.com/auth/fitness.heart_rate.write", 
          "https://www.googleapis.com/auth/fitness.location.read", 
          "https://www.googleapis.com/auth/fitness.location.write", 
          "https://www.googleapis.com/auth/fitness.heart_rate.read"
          ]
API_SERVICE_NAME = 'fitness'
API_VERSION = 'v1'

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
        

class UserGoogleFitCredentials(Model):
    __tablename__ = 'user_google_fit_credentials'
    token = CharField()
    refresh_token = CharField()
    token_uri = CharField()
    client_id = CharField()
    client_secret = CharField()
    scopes = CharField()
    user = ForeignKeyField(User, 
                           backref='user_google_fit_credentials', 
                           to_field="id", 
                           #related_name="users"
                           )
    class Meta:
        database = DATABASE

class HealthMetrics(Model):
    user = ForeignKeyField(User, 
                           to_field="id",
                           backref='health_metrics')
    heart_rate = FloatField()
    latitude = FloatField(null=True)
    longitude = FloatField(null=True)
    distance = FloatField(null=True)
    starttime = DateTimeField()
    endtime = DateTimeField()
    modifiedtime = DateTimeField()

    class Meta:
        database = DATABASE

class EmergencyContacts(Model):
    user = ForeignKeyField(User, 
                           to_field="id",
                           backref='emergency_contacts')
    contact_name = CharField(max_length=50)
    contact_number = CharField(max_length=15)
    contact_email = CharField(max_length=100)

    class Meta:
        database = DATABASE      


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/api/emergency-contact', methods=['POST'])
def add_emergency_contact():
    if request.method == 'POST':
        data = request.get_json()
        user_id = current_user.get_id()
        contact_name = data['name']
        contact_number = data['phone']
        contact_email = data['email']

        user_id = current_user.get_id()
        
        new_contact = EmergencyContacts.create(
            user=user_id,
            contact_name=contact_name,
            contact_number=contact_number,
            contact_email=contact_email,
        )
        new_contact.save()      
        return jsonify({'message': 'Emergency contact added successfully'}), 201
    
# @app.route('/api/emergency-contacts', methods=['GET'])
# def get_emergency_contacts():
#     user_id = current_user.get_id()
#     emergency_contacts = EmergencyContacts.select().where(EmergencyContacts.user == user_id)
#     emergency_contacts = [{'name': contact.contact_name, 'phone': contact.contact_number, 'email': contact.contact_email} for contact in emergency_contacts]
#     return jsonify(emergency_contacts)

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

        user = User.get(User.id == current_user.get_id())
        if user.authenticated_google_fit:
            
            try:
                credentials= UserGoogleFitCredentials.get(UserGoogleFitCredentials.user == user.id)
                session['credentials'] = {
                    'token': credentials.token,
                    'refresh_token': credentials.refresh_token,
                    'token_uri': credentials.token_uri,
                    'client_id': credentials.client_id,
                    'client_secret': credentials.client_secret,
                    'scopes': credentials.scopes
                }
            except UserGoogleFitCredentials.DoesNotExist:
                user.authenticated_google_fit = False
                user.save()
                load_user(user.id)    

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
    if 'credentials' in session:
        del session['credentials']


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
    user_id = current_user.get_id()
    emergency_contacts = EmergencyContacts.select().where(EmergencyContacts.user == user_id)
    emergency_contacts = [{'name': contact.contact_name, 'phone': contact.contact_number, 'email': contact.contact_email} for contact in emergency_contacts]  
    return render_template('emergency-form.html',emergency_contacts=emergency_contacts)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/mail-test')
def mail_test():
    msg = Message(subject='Hello from flask app!', sender='healthguardian@mailtrap.io', recipients=['sachinmoze@gmail.com','sachin.moze@gmail.com'])
    msg.body = "Hey Sachin, sending you this email from my Flask app, just checking if it works"
    mail.send(msg)
    return "Message sent!"


# @property
# def is_authenticated_google(self):
#     return session.get('is_authenticated_google_fit', False)

@app.route('/authorize-google-fit')
@login_required
def authorize_google_fit():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')
  # Store the state so the callback can verify the auth server response.
  session['state'] = state
  return redirect(authorization_url)

@app.route('/oauth2callback')
@login_required
def oauth2callback():
    try:
        # Specify the state when creating the flow in the callback so that it can
        # verified in the authorization server response.
        state = session['state']    
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
        flow.redirect_uri = url_for('oauth2callback', _external=True)   
        # Use the authorization server's response to fetch the OAuth 2.0 tokens.
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response) 
        # Store credentials in the session.
        # ACTION ITEM: In a production app, you likely want to save these
        #              credentials in a persistent database instead.
        credentials = flow.credentials
        session['credentials'] = credentials_to_dict(credentials)

        ##store the credentials in the database
        user_id = current_user.get_id()
        token = credentials.token
        refresh_token = credentials.refresh_token
        token_uri = credentials.token_uri
        client_id = credentials.client_id
        client_secret = credentials.client_secret
        scopes = credentials.scopes

        credentials = UserGoogleFitCredentials.create(
            token=token,
            refresh_token=refresh_token,
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            user=user_id 
        )
        credentials.save()

        user = User.get(User.id == current_user.get_id())
        user.authenticated_google_fit = True
        user.save()
        load_user(user.id)
        flash('Google Fit authorized successfully', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        user = User.get(User.id == current_user.get_id())
        user.authenticated_google_fit = False
        user.save()
        load_user(user.id)          
        flash(f'Error occurred while authorizing Google Fit {e}', 'danger')
        redirect(url_for('dashboard'))

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

@app.route('/revoke')
def revoke():
    try:
        user_id = current_user.get_id()
        try:
            credentials_data = UserGoogleFitCredentials.get(UserGoogleFitCredentials.user == user_id)
            credentials = {
                'token': credentials_data.token,
                'refresh_token': credentials_data.refresh_token,
                'token_uri': credentials_data.token_uri,
                'client_id': credentials_data.client_id,
                'client_secret': credentials_data.client_secret,
                'scopes': credentials_data.scopes
            }
            credentials = google.oauth2.credentials.Credentials(**session['credentials'])
            revoke = requests.post('https://oauth2.googleapis.com/revoke',
            params={'token': credentials.token},
            headers = {'content-type': 'application/x-www-form-urlencoded'})
            status_code = getattr(revoke, 'status_code')
            if status_code == 200:
                credentials_data.delete_instance()
                user = User.get(User.id == user_id)
                user.authenticated_google_fit = False
                user.save()
                load_user(user.id)
                flash('Google Fit access revoked successfully', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('An error occurred while revoking Google Fit access', 'danger')
                return redirect(url_for('dashboard'))
            
        except UserGoogleFitCredentials.DoesNotExist:
            user = User.get(User.id == user_id)
            user.authenticated_google_fit = False
            user.save()
            load_user(user.id)
            flash('Google Fit access not found, Authorize to give access', 'danger')
            return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Error occurred while revoking Google Fit {e}', 'danger')
        redirect(url_for('dashboard'))


def initialize():
    DATABASE.connect()
    DATABASE.create_tables([User,UserGoogleFitCredentials,HealthMetrics,EmergencyContacts], safe=True)
    DATABASE.close()

if __name__ == '__main__':
    initialize()
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(host='0.0.0.0',port=8080, debug=True)