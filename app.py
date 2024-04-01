from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
from flask_cors import CORS
import json
import sqlite3

app = Flask(__name__)

app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['MYSQL_HOST'] = 'health.db'
app.config['MYSQL_USER'] = 'your_username'
app.config['MYSQL_PASSWORD'] = 'your_password'
app.config['MYSQL_DB'] = 'your_database'

mysql = MySQL(app)

conn = sqlite3.connect('health.db')

cursor = conn.cursor()
cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    firstname VARCHAR(50),
    lastname VARCHAR(50),
    email VARCHAR(100) UNIQUE,
    mobilenumber VARCHAR(15),
    password VARCHAR(100) NOT NULL
        )
    """)
conn.commit()
conn.close()

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/onboarding')
def onboarding():
    return render_template('onboarding.html')


@app.route('/login')
def login():
    return render_template('login.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000, debug=True)