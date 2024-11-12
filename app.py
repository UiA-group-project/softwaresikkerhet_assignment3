#app.py
# ----------------------------------------------------------------------------#
# Imports
# ----------------------------------------------------------------------------#
import base64
import pyotp          # For generating TOTP-based 2FA codes
import qrcode         # For creating the QR code
from io import BytesIO  # To handle QR code image in memory for sending it directly to the user
from flask import send_file  # To send the QR code image to the user
from flask_login import current_user  # To access the logged-in user
from flask import Flask, render_template, request, make_response, redirect, url_for, url_for, flash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_login import LoginManager, login_user, logout_user, login_required
from config import Config
from models import User, Session, OAuthUserData, db
import logging
from logging import Formatter, FileHandler
from forms import *

# ----------------------------------------------------------------------------#
# DB Setup
# ----------------------------------------------------------------------------#



# ----------------------------------------------------------------------------#
# App Config.
# ----------------------------------------------------------------------------#

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Initialize the database
db.init_app(app)

# Create the database tables
with app.app_context():
    db.create_all()

# Login manager.
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)



# Configure Google OAuth
google_bp = make_google_blueprint(client_id=Config.GOOGLE_OAUTH_CLIENT_ID,
                                  client_secret=Config.GOOGLE_OAUTH_CLIENT_SECRET,
                                  storage=SQLAlchemyStorage(Session, db.session))
app.register_blueprint(google_bp, url_prefix="/login")



# Automatically tear down SQLAlchemy.
"""
@app.teardown_request
def shutdown_session(exception=None):
    db_session.remove()
"""

# Login required decorator.
"""
def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap
"""

# ----------------------------------------------------------------------------#
# DB requests.
# ----------------------------------------------------------------------------#



# ----------------------------------------------------------------------------#
# Controllers.
# ----------------------------------------------------------------------------#

@app.before_request
def before_request():
    if current_user.is_authenticated:
        if request.endpoint == 'show_qr_code':
            return  # Skip the redirect for the show_qr_code route
        user = load_user(current_user.id)
        if user.totp_secret is None:
            user.totp_secret = pyotp.random_base32()  # Generate a TOTP secret
            db.session.commit()
        return redirect(url_for("show_qr_code"))


@app.route("/")
def home():
    return render_template("pages/placeholder.home.html")

@app.route("/about")
@login_required
def about():
    return render_template("pages/placeholder.about.html")


@app.route("/register")
def register():
    return render_template("forms/register.html")


@app.route("/forgot")
def forgot():
    form = ForgotForm(request.form)
    return render_template("forms/forgot.html", form=form)


@app.route("/vunerableblog", methods=["GET", "POST"])
def vunerableblog():
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        # Also vunerable to SQL injection
        sqlstatement = f"INSERT INTO post (title, content) VALUES ('{title}', '{content}')"
        connection.commit()
    return render_template("pages/vunerableblog.html")


@app.route("/secureblog", methods=["GET", "POST"])
def secureblog():
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        sqlstatement = "INSERT INTO post (title, content) VALUES (?, ?)"
    
    # Add CSP header for the secure blog page
    response = make_response(render_template("pages/secureblog.html"))
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';"
    return response

@app.route("/show_qr_code")
@login_required
def show_qr_code():
    user = load_user(current_user.id)  # Retrieve the current logged-in user
    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="YourAppName")

    # Generate QR code and store it as a base64 string to embed in HTML
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_code_data = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template("layouts/show_qr_code.html", qr_code_data=qr_code_data)

@app.route("/oauth/google")
def google_login():
    if not google.authorized: # Check if user is signed in with Google
        return redirect(url_for("google.login"))
    else:
        flash("You are already signed in with Google!", "info")
        return redirect(url_for("home"))
    
@app.route("/verify_2fa", methods=["POST"])
@login_required
def verify_2fa():
    user = load_user(current_user.id)
    totp = pyotp.TOTP(user.totp_secret)
    code = request.form.get("2fa_code")

    if totp.verify(code):
        flash("2FA verification successful!", "success")
        return redirect(url_for("home"))
    else:
        flash("Invalid 2FA code. Please try again.", "error")
        return redirect(url_for("show_qr_code"))


@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    # Get user info from Google
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "error")
        return False  # Return False if fetching user info fails

    user_info = resp.json()
    # Extract fields
    user_id = user_info.get("id")
    name = user_info.get("name")
    email = "Test@gmail.com"
    given_name = user_info.get("given_name")
    family_name = user_info.get("family_name")
    picture = user_info.get("picture")

    # Check if user exists in the database
    user = User.query.get(user_id)
    if user is None:
        # Create a new user if they don't exist
        user = User(id=user_id, username=name, email="Test@gmail.com")
        db.session.add(user)
        db.session.commit()

    # Store additional user info in OAuthUserData table if necessary
    user_data = OAuthUserData.query.get(user_id)
    if user_data is None:
        user_data = OAuthUserData(
            id=user_id,
            name=name,
            given_name=given_name,
            family_name=family_name,
            picture=picture
        )
        db.session.add(user_data)
        db.session.commit()

    # Log the user in after TOTP is set up
    login_user(load_user(user_id))
    flash("Successfully signed in with Google!", "success")
    return True
   
@app.route("/logout")
def logout():
    token = google_bp.token["access_token"]
    resp = google.post(
        "https://accounts.google.com/o/oauth2/revoke",
        params={"token": token},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert resp.ok, resp.text
    logout_user()        # Delete Flask-Login's session cookie
    del google_bp.token  # Delete OAuth token from storage
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# Error handlers.


@app.errorhandler(500)
def internal_error(error):
    # db_session.rollback()
    return render_template("errors/500.html"), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template("errors/404.html"), 404


if not app.debug:
    file_handler = FileHandler("error.log")
    file_handler.setFormatter(
        Formatter("%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]")
    )
    app.logger.setLevel(logging.DEBUG)
    file_handler.setLevel(logging.DEBUG)
    app.logger.addHandler(file_handler)
    app.logger.info("errors")
    logging.getLogger('flask_dance').setLevel(logging.DEBUG)
    

# ----------------------------------------------------------------------------#
# Launch.
# ----------------------------------------------------------------------------#

# Default port:
if __name__ == "__main__":
    app.run(debug=True)

# Or specify port manually:
"""
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
"""