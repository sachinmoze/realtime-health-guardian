from peewee import SqliteDatabase, Model, CharField,IntegrityError,IntegerField,DoesNotExist,BooleanField,ForeignKeyField,DateTimeField,FloatField

from flask_login import UserMixin
from werkzeug.security import generate_password_hash
from datetime import datetime

DATABASE = SqliteDatabase('health1.db')

class User(UserMixin,Model):
    #id = IntegerField(primary_key=True)
    firstname = CharField(max_length=50)
    lastname = CharField(max_length=50)
    email = CharField(max_length=100, unique=True)
    mobilenumber = CharField(max_length=15)
    password = CharField(max_length=100)
    authenticated_google_fit = BooleanField(default=False)
    created_at = DateTimeField()

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
                password=hashed_password,
                created_at=datetime.now()
            )
            return user
        except Exception as e:
            raise Exception("Error creating user",e)
        

class UserGoogleFitCredentials(Model):
    __tablename__ = 'user_google_fit_credentials'
    token = CharField(null=True)
    refresh_token = CharField(null=True)
    token_uri = CharField(null=True)
    client_id = CharField(null=True)
    client_secret = CharField(null=True)
    scopes = CharField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(User, 
                           backref='user_google_fit_credentials', 
                           to_field="id", 
                           #related_name="users"
                           
                           )
    class Meta:
        database = DATABASE
        table_name = 'user_google_fit_credentials'

class HealthMetrics(Model):
    user = ForeignKeyField(User, 
                           to_field="id",
                           backref='health_metrics')
    heart_rate = FloatField()
    latitude = FloatField(null=True)
    longitude = FloatField(null=True)
    distance = FloatField(null=True)
    starttime = DateTimeField(unique=True)
    endtime = DateTimeField()
    modifiedtime = DateTimeField()
    updated_at = DateTimeField()

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