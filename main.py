from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import session
import os
import sqlite3 as sql
import pyotp
import pyqrcode
import base64
from io import BytesIO
from urllib.parse import urlparse
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
import user_management as dbHandler

app = Flask(__name__)
# secret key for csrf
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise ValueError("SECRET_KEY environment variable must be set")

# add 2fa column to database
def init_db():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cur.fetchall()]
    if "twofa_secret" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN twofa_secret TEXT")
        con.commit()
    con.close()

init_db()

# session cookie security settings
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

csrf = CSRFProtect(app)


# add security headers
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # content security policy
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    return response


class CSRFOnlyForm(FlaskForm):
    pass


@app.route("/success.html", methods=["POST", "GET"])
def addFeedback():
    form = CSRFOnlyForm()
    
    # check if user is logged in
    if "username" not in session:
        return redirect("/?msg=Please login first")
    
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        # parse url to check if local
        parsed_url = urlparse(url)
        # netloc empty for relative urls
        if url and not parsed_url.netloc:
            return redirect(url, code=302)
        else:
            return redirect("/success.html")
    
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value=session["username"], form=form)
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value=session["username"], form=form)


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    form = CSRFOnlyForm()
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        # parse url to check if local
        parsed_url = urlparse(url)
        # netloc empty for relative urls
        if url and not parsed_url.netloc:
            return redirect(url, code=302)
        else:
            return redirect("/signup.html")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isUserCreated = dbHandler.insertUser(username, password, "")
        if isUserCreated:
            # generate 2fa secret
            session["username"] = username
            session["2fa_secret"] = pyotp.random_base32()
            # redirect to 2fa setup
            return redirect("/2fa-setup.html")
        else:
            return render_template(
                "/signup.html", msg="Password must be at least 8 characters.", form=form
            )
    else:
        return render_template("/signup.html", form=form)


@app.route("/2fa-setup.html", methods=["POST", "GET"])
def two_factor_setup():
    form = CSRFOnlyForm()
    
    # check signup process
    if "username" not in session or "2fa_secret" not in session:
        return redirect("/?msg=Please sign up first")
    
    if request.method == "GET":
        # generate qr code
        username = session["username"]
        user_secret = session["2fa_secret"]
        
        totp = pyotp.TOTP(user_secret)
        otp_uri = totp.provisioning_uri(name=username, issuer_name="UnsecurePWA")
        
        qr_code = pyqrcode.create(otp_uri)
        stream = BytesIO()
        qr_code.png(stream, scale=5)
        
        qr_code_b64 = base64.b64encode(stream.getvalue()).decode('utf-8')
        
        return render_template("/2fa-setup.html", username=username, qr_code=qr_code_b64, form=form)
    
    if request.method == "POST":
        # verify otp code entered
        otp_input = request.form.get("otp", "")
        user_secret = session["2fa_secret"]
        totp = pyotp.TOTP(user_secret)
        
        if totp.verify(otp_input):
            # save 2fa secret to database
            dbHandler.save2FASecret(session["username"], user_secret)
            session.pop("2fa_secret", None)
            return render_template(
                "/success.html", value=session["username"], state=True, form=form
            )
        else:
            # invalid otp show error
            return render_template("/2fa-setup.html", username=session["username"], 
                                 qr_code=None, error="Invalid code. Please try again.", form=form)


@app.route("/2fa-login.html", methods=["POST", "GET"])
def two_factor_login():
    form = CSRFOnlyForm()
    
    # check if user is logged in
    if "username" not in session:
        return redirect("/?msg=Please login first")
    
    if request.method == "POST":
        # verify otp code entered
        otp_input = request.form.get("otp", "")
        
        # get stored 2fa secret
        stored_secret = dbHandler.get2FASecret(session["username"])
        
        if stored_secret:
            totp = pyotp.TOTP(stored_secret)
            if totp.verify(otp_input):
                # otp valid user authenticated
                dbHandler.listFeedback()
                return render_template(
                    "/success.html", value=session["username"], state=True, form=form
                )
            else:
                # invalid otp show error
                return render_template("/2fa-login.html", username=session["username"], 
                                     error="Invalid code. Please try again.", form=form)
        else:
            # no 2fa setup found
            return render_template("/2fa-login.html", username=session["username"], 
                                 error="2FA not set up. Please contact support.", form=form)
    
    # show 2fa login page
    return render_template("/2fa-login.html", username=session["username"], form=form)


@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def home():
    form = CSRFOnlyForm()
    
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        # Parse the URL to check if it's a local relative path
        parsed_url = urlparse(url)
        # netloc is empty for relative URLs like "/index.html"
        # netloc has a value for absolute URLs like "http://evil.com"
        if url and not parsed_url.netloc:
            return redirect(url, code=302)
        else:
            return redirect("/")
    
    # pass message to front end
    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg, form=form)
    
    # handle login
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            # store username in session
            session["username"] = username
            # check if user has 2fa
            has_2fa = dbHandler.get2FASecret(username)
            if has_2fa:
                # redirect to 2fa verification
                return redirect("/2fa-login.html")
            else:
                # no 2fa go to success
                dbHandler.listFeedback()
                return render_template(
                    "/success.html", value=username, state=isLoggedIn, form=form
                )
        else:
            return render_template("/index.html", form=form)
    
    return render_template("/index.html", form=form)


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=False, host="127.0.0.1", port=5000)
