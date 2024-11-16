import sqlite3
import requests, os, subprocess, jwt
from flask import Flask, request, jsonify, redirect, render_template, url_for, session, g, make_response
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "supersecretkey"
jwt_secret = "secret" 

DATABASE = 'vulnerable_app.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
        cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin')")
        cursor.execute("INSERT INTO users (username, password) VALUES ('jack', 'crackjack')")
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def home():
    return redirect(url_for('blog', id=1))

@app.route('/blog')
def blog():
    blog_id = request.args.get('id')
    if blog_id == '1':
        return render_template("blog1.html")
    elif blog_id == '2':
        return render_template("blog2.html")
    else:
        error_message = f"Invalid blog ID: '{blog_id}'. Please make sure you use a valid ID like '1' or '2'."
        return f"<h1>404 Error: Blog Not Found</h1><p>{error_message}</p>", 404

@app.route('/areyouthere', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        query = f"SELECT * FROM users WHERE username = '{username}'"
        db = get_db()
        cursor = db.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            if user[1] == password:
                # Generate JWT token
                token = jwt.encode({"username": username}, jwt_secret, algorithm="HS256")
                
                # Set JWT as a cookie and redirect to admin_dashboard
                response = make_response(redirect(url_for('admin_dashboard')))
                response.set_cookie('jwt', token)
                return response
            else:
                return render_template('login.html', error=f"Wrong password for user {username}")
        else:
            return render_template('login.html', error=f"User {username} is not a valid user")
    
    return render_template('login.html', error=None)

def verify_jwt(token):
    try:
        decoded_token = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        return decoded_token
    except jwt.InvalidTokenError:
        return None

@app.route('/admin_dashboard')
def admin_dashboard():
    token = request.cookies.get('jwt')
    if token:
        decoded_token = verify_jwt(token)
        if decoded_token:
            username = decoded_token["username"]
            return render_template('admin_dashboard.html', username=username)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # Remove the JWT token from the cookies
    response = make_response(redirect(url_for('home')))
    response.set_cookie('jwt', '', expires=0)  # Clear the JWT cookie
    
    # Get the 'redirect' parameter from the query string
    redirect_url = request.args.get('redirect')

    # Check if a redirect URL is provided
    if redirect_url:
        # Vulnerable open redirect: directly redirect to the provided URL
        response = make_response(redirect(redirect_url))  # Redirect to the user-supplied URL
    else:
        # Default to home page if no redirect URL is provided
        response = make_response(redirect(url_for('home')))

    # Add custom header with hardcoded URL
    response.headers['X-Custom-Redirect-Path'] = 'redirect= + url'
    
    # Return the response object with the custom header
    return response


@app.route('/admin_dashboard/isexists', methods=['GET'])
def is_exists():
    url = request.args.get('url')
    try:
        command = f"wget -qO- {url}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return jsonify({"error": "Failed to fetch the URL"}), 400
        return jsonify({"message": "Valid!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/validdomain')
def valid_domain():
    return render_template('isvaliddomain.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=False, port=5001)

