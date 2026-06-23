from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import session
import os
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
import user_management as dbHandler

# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)
# Secret key for CSRF protection
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise ValueError("SECRET_KEY environment variable must be set")

csrf = CSRFProtect(app)


class CSRFOnlyForm(FlaskForm):
    pass


@app.route("/success.html", methods=["POST", "GET"])
def addFeedback():
    form = CSRFOnlyForm()
    
    # Check if user is logged in
    if "username" not in session:
        return redirect("/?msg=Please login first")
    
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        # Only allow relative URLs to prevent open redirect attacks
        if url and not url.startswith('http'):
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
        # Only allow relative URLs to prevent open redirect attacks
        if url and not url.startswith('http'):
            return redirect(url, code=302)
        else:
            return redirect("/signup.html")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]
        isUserCreated = dbHandler.insertUser(username, password, DoB)
        if isUserCreated:
            return render_template("/index.html", form=form)
        else:
            return render_template(
                "/signup.html", msg="Password must be at least 8 characters.", form=form
            )
    else:
        return render_template("/signup.html", form=form)


@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def home():
    form = CSRFOnlyForm()
    
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        # Only allow relative URLs to prevent open redirect attacks
        if url and not url.startswith('http'):
            return redirect(url, code=302)
        else:
            return redirect("/")
    
    # Pass message to front end
    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg, form=form)
    
    # Handle login
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            # Store username in session
            session["username"] = username
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
