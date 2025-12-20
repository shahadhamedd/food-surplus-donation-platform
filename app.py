from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "mysecret123"   # For login sessions

# ----------------------------
# Database Setup
# ----------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"

db = SQLAlchemy(app)

# ----------------------------
# Models
# ----------------------------
class Provider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(300))
    address = db.Column(db.String(200))
    category = db.Column(db.String(100))
    verification_status = db.Column(db.String(50), default="Pending")
    created_at = db.Column(db.String(50))
    image = db.Column(db.String(200))

class Beneficiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(300))
    address = db.Column(db.String(200))
    category = db.Column(db.String(100))
    created_at = db.Column(db.String(50))
    document = db.Column(db.String(200))

with app.app_context():
    db.create_all()


# ------------------------------------------------
# STATIC FILES
# ------------------------------------------------
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ------------------------------------------------
# HOME / CHOOSE ROLE
# ------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/choose-role")
def choose_role():
    return render_template("choose_role.html")


# ------------------------------------------------
# PROVIDER REGISTRATION
# ------------------------------------------------

@app.route("/provider/options")
def provider_options():
    return render_template("provider_options.html")


@app.route("/register/provider/<category>", methods=["GET", "POST"])
def register_provider(category):

    if request.method == "POST":
        full_name = request.form["full_name"]
        phone = request.form["phone"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        address = request.form["address"]
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M")

        file = request.files.get("image")

        filename = None
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        new_user = Provider(
            full_name=full_name,
            phone=phone,
            email=email,
            password=password,
            address=address,
            category=category,
            verification_status="Pending",
            created_at=created_at,
            image=filename
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("success", msg=f"تم تسجيلك كمزود بنجاح!", user_id=new_user.id, role="provider"))

    return render_template("provider_register.html", category=category)



# ------------------------------------------------
# BENEFICIARY REGISTRATION
# ------------------------------------------------

@app.route("/beneficiary/options")
def beneficiary_options():
    return render_template("beneficiary_options.html")


@app.route("/register/beneficiary/<category>", methods=["GET", "POST"])
def register_beneficiary(category):

    if request.method == "POST":
        full_name = request.form["full_name"]
        phone = request.form["phone"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        address = request.form["address"]
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M")

        file = request.files.get("document")

        filename = None
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        new_user = Beneficiary(
            full_name=full_name,
            phone=phone,
            email=email,
            password=password,
            address=address,
            category=category,
            created_at=created_at,
            document=filename
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("success", msg=f"تم تسجيلك بنجاح!", user_id=new_user.id, role="beneficiary"))

    return render_template("beneficiary_register.html", category=category)



# ------------------------------------------------
# SUCCESS PAGE
# ------------------------------------------------

@app.route("/success")
def success():
    msg = request.args.get("msg")
    user_id = request.args.get("user_id")
    role = request.args.get("role")

    user = None
    if role == "provider":
        user = Provider.query.get(user_id)
    elif role == "beneficiary":
        user = Beneficiary.query.get(user_id)

    return render_template("success.html", msg=msg, user=user, role=role)


# ------------------------------------------------
# LOGIN SYSTEM
# ------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Provider
        provider = Provider.query.filter_by(email=email).first()
        if provider and check_password_hash(provider.password, password):
            session["user_id"] = provider.id
            session["role"] = "provider"
            return redirect(url_for("provider_dashboard"))

        # Beneficiary
        beneficiary = Beneficiary.query.filter_by(email=email).first()
        if beneficiary and check_password_hash(beneficiary.password, password):
            session["user_id"] = beneficiary.id
            session["role"] = "beneficiary"
            return redirect(url_for("beneficiary_dashboard"))

        error = "خطأ في الإيميل أو كلمة المرور"

    return render_template("login.html", error=error)


# ------------------------------------------------
# DASHBOARD PAGES
# ------------------------------------------------

@app.route("/provider/dashboard")
def provider_dashboard():
    if "user_id" not in session or session["role"] != "provider":
        return redirect(url_for("login"))

    user = Provider.query.get(session["user_id"])
    return f"<h1>Welcome Provider: {user.full_name}</h1>"


@app.route("/beneficiary/dashboard")
def beneficiary_dashboard():
    if "user_id" not in session or session["role"] != "beneficiary":
        return redirect(url_for("login"))

    user = Beneficiary.query.get(session["user_id"])
    return f"<h1>Welcome Beneficiary: {user.full_name}</h1>"


# ------------------------------------------------
# LOGOUT
# ------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------
# RUN APP
# ------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)