import os
import numpy as np
import joblib
import sqlite3
import logging
import warnings
from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

# Suppress warnings
warnings.filterwarnings('ignore')

# Flask App Initialization
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure session key

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ---------------------- ROUTES ----------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/about")
def about():
    return render_template("about.html")

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/logon')
def logon():
    return render_template('signup.html')

@app.route('/login')
def login():
    return render_template('signin.html')

# ---------------------- SIGNUP ----------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        try:
            username = request.form.get('user', '')
            name = request.form.get('name', '')
            email = request.form.get('email', '')
            mobile = request.form.get('mobile', '')
            password = generate_password_hash(request.form.get('password', ''), method='pbkdf2:sha256')


            with sqlite3.connect('signup.db') as con:
                cur = con.cursor()
                cur.execute('''CREATE TABLE IF NOT EXISTS info (
                                user TEXT PRIMARY KEY, 
                                email TEXT, 
                                password TEXT, 
                                mobile TEXT, 
                                name TEXT)''')
                cur.execute("INSERT INTO info (user, email, password, mobile, name) VALUES (?, ?, ?, ?, ?)",
                            (username, email, password, mobile, name))
                con.commit()

                logging.info("✅ Signup Successful, Redirecting to Signin")
                return redirect(url_for("signin"))  # Redirect to login page after signup

        except sqlite3.Error as e:
            logging.error(f"⚠️ Database Error: {e}")
            return render_template("signup.html", error="Database Error. Try again.")

    return render_template("signup.html")

# ---------------------- SIGNIN ----------------------

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        mail1 = request.form.get('user', '')
        password1 = request.form.get('password', '')

        with sqlite3.connect('signup.db') as con:
            cur = con.cursor()
            cur.execute("SELECT user, password FROM info WHERE user = ?", (mail1,))
            data = cur.fetchone()

        if data and check_password_hash(data[1], password1):
            session["user"] = mail1  # Store user session
            logging.info("✅ Login Successful, Redirecting to Predict Page")
            return redirect(url_for("predict"))  # Redirect to prediction page

        logging.warning("❌ Invalid Login Attempt")
        return render_template("signin.html", error="Invalid credentials. Try again.")

    return render_template("signin.html")

# ---------------------- PREDICTION ----------------------

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if "user" not in session:
        return redirect(url_for("signin"))  # Redirect to sign-in if not logged in

    if request.method == "POST":
        try:
            int_features = [float(x) for x in request.form.values()]
            final_features = np.array([int_features])

            model = joblib.load('model.sav')  # Load trained model
            prediction = model.predict(final_features)[0]

            attack_types = {
                0: 'There is an Attack Detected, Attack Type is DDoS!',
                1: 'There is an Attack Detected, Attack Type is Probe!',
                2: 'There is an Attack Detected, Attack Type is R2L!',
                3: 'There is an Attack Detected, Attack Type is U2R!',
                4: 'There is No Attack Detected, it is Normal!'
            }

            output = attack_types.get(prediction, "Unknown Prediction")
            return render_template('prediction.html', output=output)

        except Exception as e:
            logging.error(f"Prediction Error: {e}")
            return render_template("prediction.html", output="Error in prediction. Try again.")

    return render_template("prediction.html")

# ---------------------- NOTEBOOK ROUTE ----------------------

@app.route("/notebook")
def notebook1():
    return render_template("Notebook.html")

# ---------------------- LOGOUT ----------------------

@app.route("/logout")
def logout():
    session.pop("user", None)
    logging.info("✅ User Logged Out")
    return redirect(url_for("signin"))

# ---------------------- MAIN ----------------------

if __name__ == "__main__":
    app.run(debug=True)


