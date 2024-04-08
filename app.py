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
from db_models import User,UserGoogleFitCredentials,HealthMetrics,EmergencyContacts,DATABASE
from flask_mail import Mail, Message

import os
from dotenv import load_dotenv, dotenv_values 
load_dotenv() 

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from googleapiclient.discovery import build
import google.auth.transport.requests

import requests

from celery import Celery
#import config
import redis
from datetime import datetime, timedelta,timezone
#from tasks import flask_app, long_running_task #-Line 1
from celery.result import AsyncResult#-Line 2

CLIENT_SECRETS_FILE = "credentials.json"

SCOPES = ['https://www.googleapis.com/auth/fitness.activity.read',
           "https://www.googleapis.com/auth/fitness.blood_glucose.read", 
          "https://www.googleapis.com/auth/fitness.heart_rate.write", 
          "https://www.googleapis.com/auth/fitness.location.read", 
          "https://www.googleapis.com/auth/fitness.location.write", 
          "https://www.googleapis.com/auth/fitness.blood_glucose.write",
            "https://www.googleapis.com/auth/fitness.sleep.read",
              "https://www.googleapis.com/auth/fitness.body.read", 
              "https://www.googleapis.com/auth/fitness.oxygen_saturation.read", 
              "https://www.googleapis.com/auth/fitness.sleep.write",
              "https://www.googleapis.com/auth/fitness.body.write", 
              "https://www.googleapis.com/auth/fitness.oxygen_saturation.write", 
              "https://www.googleapis.com/auth/fitness.body_temperature.read", 
              "https://www.googleapis.com/auth/fitness.nutrition.read", 
              "https://www.googleapis.com/auth/fitness.body_temperature.write", 
              "https://www.googleapis.com/auth/fitness.nutrition.write", 
              "https://www.googleapis.com/auth/fitness.reproductive_health.read", 
              "https://www.googleapis.com/auth/fitness.activity.read", 
              "https://www.googleapis.com/auth/fitness.blood_pressure.read", 
              "https://www.googleapis.com/auth/fitness.reproductive_health.write", 
              "https://www.googleapis.com/auth/fitness.activity.write", 
              "https://www.googleapis.com/auth/fitness.blood_pressure.write", 
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


@login_manager.user_loader
def load_user(user_id):
    return User.get(User.id == user_id)

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
    
@app.route('/delete-emergency-contact', methods=['DELETE'])
def delete_emergency_contact():
    print('running in delete')
    print(request.method)
    if request.method == 'DELETE':
        data = request.get_json()
        print(data)
        contact_id = data['id']
        email = data['email']
        name = data['name']
        phone = data['phone']
        user_id = data["user_id"]
        try:
            if contact_id == "null":
                EmergencyContacts.delete().where(EmergencyContacts.contact_name == name, EmergencyContacts.contact_number == phone,
                                                  EmergencyContacts.contact_email == email,
                                                  EmergencyContacts.user_id == user_id
                                                  ).execute()
                return jsonify({'message': 'Emergency contact deleted successfully'}), 200
            else:
                contact = EmergencyContacts.get(EmergencyContacts.id == contact_id)
                contact.delete_instance()
                return jsonify({'message': 'Emergency contact deleted successfully'}), 200
        except DoesNotExist:
            print('Emergency contact not found')
            return jsonify({'message': 'Emergency contact not found'}), 404
          

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
        print('User is authenticated already. Redirecting to dashboard.')
        user = User.get(User.id == current_user.get_id())

        if user.authenticated_google_fit:
            
            try:
                credentials= UserGoogleFitCredentials.get(UserGoogleFitCredentials.user == user.id)
                #session['credentials'] = credentials_to_dict(credentials)
            except UserGoogleFitCredentials.DoesNotExist:
                user.authenticated_google_fit = False
                user.save()
                load_user(user.id)    

        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        print('Login form submitted successfully. Processing form data.')
        email = request.form.get('email')
        password = request.form.get('password')
       
        if not User.user_exists(email):
            flash('Email id does not exist. Please sign up.', 'danger')
            return redirect(url_for('login'))

        user = User.get(User.email == email)
        print(user.id)
        print("hello ",user.firstname)
        if check_password_hash(user.password, password):
            login_user(user)
            print('User logged in successfully.')
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
    emergency_contacts = [{'name': contact.contact_name, 'phone': contact.contact_number, 'email': contact.contact_email,'id':contact.id,'user_id':contact.user_id} for contact in emergency_contacts]  
    return render_template('emergency-form.html',emergency_contacts=emergency_contacts)

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = current_user.get_id()
    print(user_id)

    return render_template('dashboard.html')

@app.route('/mail-test')
def mail_test():
    msg = Message(subject='Hello from flask app!', sender='healthguardian@mailtrap.io', recipients=['sachinmoze@gmail.com','sachin.moze@gmail.com'])
    msg.body = "Hey Sachin, sending you this email from my Flask app, just checking if it works"
    mail.send(msg)
    return "Message sent!"


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
        print("running in oauth2callback") 
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
        flow.redirect_uri = url_for('oauth2callback', _external=True)  
        flow.access_type = 'offline' 
        # Use the authorization server's response to fetch the OAuth 2.0 tokens.
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response) 
        # Store credentials in the session.
        # ACTION ITEM: In a production app, you likely want to save these
        #              credentials in a persistent database instead.
        credentials = flow.credentials
        #session['credentials'] = credentials_to_dict(credentials)

        ##store the credentials in the database
        user_id = current_user.get_id()
        print("Storing google fit credentials in the database")
        token = credentials.token

        #print("Token",token,type(token))
        refresh_token = credentials.refresh_token
        #print("Refresh Token",refresh_token,type(refresh_token))
        token_uri = credentials.token_uri
        #print("Token URI",token_uri,type(token_uri))
        client_id = credentials.client_id
        #print("Client ID",client_id,type(client_id))
        client_secret = credentials.client_secret
        #print("Client Secret",client_secret,type(client_secret))
        scopes = credentials.scopes
        #print("Scopes",scopes,type(scopes))
        credentials = UserGoogleFitCredentials.create(
            token=token,
            refresh_token=refresh_token,
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            user_id=user_id,
            updated_at=datetime.now() 
        )
        credentials.save()
        print("Credentials stored successfully")
        user = User.get(User.id == current_user.get_id())
        user.authenticated_google_fit = True
        user.save()
        load_user(user.id)

        flash('Google Fit authorized successfully', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        print("Error occurred while authorizing Google Fit",e)
        user = User.get(User.id == current_user.get_id())
        user.authenticated_google_fit = False
        user.save()
        load_user(user.id)          
        flash(f'Error occurred while authorizing Google Fit {e}', 'danger')
        redirect(url_for('dashboard'))

def credentials_to_dict(credentials):
  print("running in credentials to dict")
  print(type(credentials.scopes))
  if not isinstance(credentials.scopes, list):
      print("converting scopes to list")
      scopes=eval(credentials.scopes)
  else:
      scopes = credentials.scopes   
  #print(scopes)
  print(type(scopes))     
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': scopes}

def nanos_to_datetime(nanos):
    # Convert nanoseconds to seconds
    seconds = int(nanos) / 1e9
    # Convert seconds to datetime 
    utc_datetime = datetime.fromtimestamp(seconds, timezone.utc)
    # Convert UTC datetime to GMT
    gmt_datetime = utc_datetime.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S GMT')
    return gmt_datetime

def millis_to_datetime(millis):
    # Convert milliseconds to seconds
    seconds = int(millis) / 1000
    # Convert seconds to datetime object
    utc_datetime = datetime.fromtimestamp(seconds, timezone.utc)
    # Convert UTC datetime to GMT
    gmt_datetime = utc_datetime.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S GMT')
    return gmt_datetime

@app.route('/store-heart-rate')
def store_heartrate_data():
    user_id = current_user.get_id()
    params = {"user_id": user_id,"data_type":"all"}
    response = requests.get('http://localhost:8080/api/fetch-heart-rate',params=params)  # Update the URL with your actual server URL

    #return response.json()['response']
    if response.status_code == 200:
        health_metrics = response.json()['response']
        #"deletedDataPoint",
        data_points=["insertedDataPoint"]
        #update_google_fit_credentials(user_id,response.json()['updated_creds'])
        for data_point in data_points:
            for metric in health_metrics.get(data_point):

                heart_rate = metric["value"][0]["fpVal"]

                starttime = nanos_to_datetime(metric.get('startTimeNanos'))
                endtime = nanos_to_datetime(metric.get('endTimeNanos'))
                modifiedtime = millis_to_datetime(metric.get('modifiedTimeMillis'))
                latitude = 0
                longitude = 0
                distance = 0

                if HealthMetrics.select().where((HealthMetrics.starttime == starttime) & (HealthMetrics.user_id==user_id)).exists():
                    pass
                else:
                    print("Updating heart rate",heart_rate)
                    health_metrics = HealthMetrics.create(
                        user=user_id,
                        heart_rate=heart_rate,
                        latitude=latitude,
                        longitude=longitude,
                        distance=distance,
                        starttime=starttime,
                        endtime=endtime,
                        modifiedtime=modifiedtime,
                        updated_at=datetime.now()
                    )
                    health_metrics.save()
        flash("updated data to database", 'success')
        return redirect('dashboard')
    else:
        flash(f"Error occurred while fetching heart rate data {response.json()['response']}", 'danger')
        return redirect('dashboard')

@app.route('/store-heart-rate-new')
def store_heartrate_data_today():
    user_id = current_user.get_id()
    starttime = datetime.now() - timedelta(days=1) 
    endtime = datetime.now()
    params = {"user_id": user_id,"starttime":starttime,"endtime":endtime,"data_type":"today"}
    response = requests.get('http://localhost:8080/api/fetch-heart-rate',params=params)  # Update the URL with your actual server URL

    if response.status_code == 200:
        health_metrics = response.json()['response']
        #"deletedDataPoint",
        data_points=["point"]
        
        for data_point in data_points:
            for metric in health_metrics.get(data_point):

                heart_rate = metric["value"][0]["fpVal"]

                starttime = nanos_to_datetime(metric.get('startTimeNanos'))
                endtime = nanos_to_datetime(metric.get('endTimeNanos'))
                modifiedtime = millis_to_datetime(metric.get('modifiedTimeMillis'))
                latitude = 0
                longitude = 0
                distance = 0

                if HealthMetrics.select().where((HealthMetrics.starttime == starttime) & (HealthMetrics.user_id==user_id)).exists():
                    #print("Data already exists",heart_rate)
                    pass
                else:
                    print("Updating heart rate",heart_rate)
                    health_metrics = HealthMetrics.create(
                        user=user_id,
                        heart_rate=heart_rate,
                        latitude=latitude,
                        longitude=longitude,
                        distance=distance,
                        starttime=starttime,
                        endtime=endtime,
                        modifiedtime=modifiedtime,
                        updated_at=datetime.now()
                    )
                    health_metrics.save()
        flash("updated data to database", 'success')
        return redirect('dashboard')
    else:
        flash(f"Error occurred while fetching heart rate data {response.json()['response']}", 'danger')
        return redirect('dashboard')

def update_google_fit_credentials(user_id, credentials_data):
    user_id = user_id
    credentials = UserGoogleFitCredentials.get(UserGoogleFitCredentials.user == user_id)
    if credentials:
        # Check if all parameters are the same
        if (credentials.token == credentials_data.get('token') and
            credentials.refresh_token == credentials_data.get('refresh_token') and
            credentials.token_uri == credentials_data.get('token_uri') and
            credentials.client_id == credentials_data.get('client_id') and
            credentials.client_secret == credentials_data.get('client_secret') and
            credentials.scopes == credentials_data.get('scopes')):
            print("All parameters are the same. No update needed.")
        
        else:
            credentials.token = credentials_data.get('token')
            credentials.refresh_token = credentials_data.get('refresh_token')
            credentials.token_uri = credentials_data.get('token_uri')
            credentials.client_id = credentials_data.get('client_id')
            credentials.client_secret = credentials_data.get('client_secret')
            credentials.scopes = credentials_data.get('scopes')
            # Save the updated credentials
            credentials.save()
            print("Credentials updated successfully.")
    else:
        print("Credentials not found for the user.")


def create_fitness_service_and_get_data_all(credentials):
    
    print("running in create fitness service and get data")
    #session['credentials'] = credentials

    credentials_obj = google.oauth2.credentials.Credentials(**credentials)
    #credentials_obj = google.oauth2.credentials.Credentials(**session['credentials'])
    # Check if the access token is expired
    if credentials_obj.expired:
        # Refresh the token
        request = google.auth.transport.requests.Request()
        credentials_obj.refresh(request)

        # Update the credentials in the session
        #session['credentials'] = credentials_to_dict(credentials_obj)    
    
    fitness_service = build(API_SERVICE_NAME, API_VERSION, credentials=credentials_obj)
    heart_rate_data = fitness_service.users().dataSources().dataPointChanges().list(userId='me',
                                                                                               dataSourceId='derived:com.google.heart_rate.bpm:com.google.android.gms:merge_heart_rate_bpm').execute()
    
    #session['credentials'] = credentials_to_dict(credentials_obj)
      
    return heart_rate_data, credentials_to_dict(credentials_obj)    

def create_fitness_service_and_get_data_today(credentials, dataset_id):

    print("Running in create_fitness_service_and_get_data to fetch today data")

    credentials_obj = google.oauth2.credentials.Credentials(**credentials)
    #credentials_obj = google.oauth2.credentials.Credentials(**session['credentials'])
    # Check if the access token is expired
    if credentials_obj.expired:
        # Refresh the token
        request = google.auth.transport.requests.Request()
        credentials_obj.refresh(request)    
    #credentials_obj = google.oauth2.credentials.Credentials(**credentials)
    fitness_service = build(API_SERVICE_NAME, API_VERSION, credentials=credentials_obj)

    # Execute API request to retrieve data for the specified dataset ID
    data = fitness_service.users().dataSources().datasets().get(
        userId='me',
        dataSourceId="derived:com.google.heart_rate.bpm:com.google.android.gms:merge_heart_rate_bpm",
        datasetId=dataset_id
    ).execute()

    # Update session credentials
    #session['credentials'] = credentials_to_dict(credentials_obj)

    # Return the retrieved data and credentials
    return data, credentials_to_dict(credentials_obj)

def datetime_to_nanos(dt):
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt)  # Convert string to datetime object
    # Convert datetime object to seconds since epoch
    seconds = dt.timestamp()
    # Convert seconds to nanoseconds
    nanos = seconds * 1e9
    return int(nanos)

@app.route('/api/fetch-heart-rate', methods=['GET'])
#@login_required
def fetch_heart_rate():
    try:
        user_id = request.args.get('user_id')
        data_type = request.args.get('data_type')
        starttime= request.args.get('starttime')
        endtime = request.args.get('endtime')
        credentials_data = UserGoogleFitCredentials.get(UserGoogleFitCredentials.user_id == user_id)
        credentials = credentials_to_dict(credentials_data)
        
        # Fetch heart rate data and update session credentials
        if data_type.lower() == "all":
            heart_rate_data, new_creds = create_fitness_service_and_get_data_all(credentials)
        if data_type.lower() == "today":
            start=str(datetime_to_nanos(starttime))
            end = str(datetime_to_nanos(endtime))
            dataset_id = start + "-" + end
            heart_rate_data, new_creds = create_fitness_service_and_get_data_today(credentials, dataset_id)
        
        update_google_fit_credentials(user_id, new_creds) 
        
        # Return the heart rate data as JSON response
        return jsonify({"response": heart_rate_data}),200
        
    except UserGoogleFitCredentials.DoesNotExist:
        user = User.get(User.id == user_id)
        user.authenticated_google_fit = False
        user.save()
        load_user(user.id)
        jsonify({"response": "Google Fit access not found, Authorize to give access"}),404 
        
    except Exception as e:
        return jsonify({"response": f'Error occurred while fetching heart rate: {e}'}),500

@app.route('/revoke-google-fit-cred')
@login_required
def revoke_google_fit_cred():
    print("running in revoke")
    try:
        
        print("running in revoke")
        user_id = current_user.get_id()
        print(user_id)
        #print(session['credentials'])
        try:
            credentials_data = UserGoogleFitCredentials.get(UserGoogleFitCredentials.user == user_id)
            credentials = credentials_to_dict(credentials_data)

            session['credentials'] = credentials
            #credentials = google.oauth2.credentials.Credentials(**session['credentials'])
            credentials = google.oauth2.credentials.Credentials(**credentials)
            revoke = requests.post('https://oauth2.googleapis.com/revoke',
                params={'token': credentials.token},
                headers = {'content-type': 'application/x-www-form-urlencoded'}
                )
            status_code = getattr(revoke, 'status_code')
            if status_code == 200:
                credentials_data.delete_instance()
                user = User.get(User.id == user_id)
                user.authenticated_google_fit = False
                user.save()
                load_user(user.id)
                session.pop('credentials', None)
                flash('Google Fit access revoked successfully', 'success')
                return redirect(url_for('dashboard'))
            else:
                credentials_data.delete_instance()
                user = User.get(User.id == user_id)
                user.authenticated_google_fit = False
                user.save()
                load_user(user.id)
                session.pop('credentials', None)                
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