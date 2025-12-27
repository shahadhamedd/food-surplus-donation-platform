from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = "mysecret123"
app.permanent_session_lifetime = timedelta(days=7)

# ============================
# OWNER PIN (Only this PIN)
# ============================
OWNER_PIN = "4444"

# ----------------------------
# Database + Uploads
# ----------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)

# ----------------------------
# Models
# ----------------------------
class Provider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    verification_status = db.Column(db.String(50), default="Pending")
    created_at = db.Column(db.String(50))
    image = db.Column(db.String(200))


class Beneficiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.String(50))
    document = db.Column(db.String(200))


class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider_id = db.Column(db.Integer, db.ForeignKey("provider.id"), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(400))
    quantity = db.Column(db.String(80))
    category = db.Column(db.String(100))
    status = db.Column(db.String(30), default="Pending")
    created_at = db.Column(db.String(50))

    provider = db.relationship("Provider", backref=db.backref("donations", lazy=True))


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey("donation.id"), nullable=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey("beneficiary.id"), nullable=False)
    status = db.Column(db.String(30), default="Pending")
    created_at = db.Column(db.String(50))

    donation = db.relationship("Donation", backref=db.backref("requests", lazy=True))
    beneficiary = db.relationship("Beneficiary", backref=db.backref("requests", lazy=True))


with app.app_context():
    db.create_all()

# ----------------------------
# Helpers
# ----------------------------
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def save_uploaded_file(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    filename = secure_filename(file_storage.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file_storage.save(path)
    return filename


def redirect_if_logged_in():
    if session.get("user_id"):
        role = session.get("role")
        if role == "provider":
            return redirect(url_for("provider_dashboard"))
        if role == "beneficiary":
            return redirect(url_for("beneficiary_dashboard"))
    return None


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                # redirect to login with role if provided
                return redirect(url_for("login", role=role) if role else url_for("login"))
            if role and session.get("role") != role:
                session.clear()
                return redirect(url_for("login", role=role))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def owner_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("owner"):
            return redirect(url_for("owner_login"))
        return fn(*args, **kwargs)
    return wrapper


def template_exists(name: str) -> bool:
    return os.path.exists(os.path.join(app.root_path, "templates", name))


# ----------------------------
# Static uploads route
# ----------------------------
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ============================================================
# MAIN PAGE
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard_redirect():
    r = redirect_if_logged_in()
    if r:
        return r
    return redirect(url_for("login"))


@app.route("/home")
def home():
    return redirect(url_for("index"))


@app.route("/main")
def main_page():
    return redirect(url_for("index"))


# ----------------------------
# Choose Role
# ----------------------------
@app.route("/choose-role")
def choose_role():
    return render_template("choose_role.html")


@app.route("/switch-role")
def switch_role():
    owner_flag = session.get("owner")
    session.clear()
    if owner_flag:
        session["owner"] = True
    return redirect(url_for("choose_role"))


# ----------------------------
# Provider options + register
# ----------------------------
@app.route("/provider/options")
def provider_options():
    r = redirect_if_logged_in()
    if r and session.get("role") == "provider":
        return r
    return render_template("provider_options.html")


@app.route("/register/provider/<category>", methods=["GET", "POST"])
def register_provider(category):
    if session.get("user_id"):
        return redirect(url_for("provider_dashboard"))

    if request.method == "POST":
        full_name = request.form["full_name"]
        phone = request.form["phone"]
        email = request.form["email"].strip().lower()
        password = generate_password_hash(request.form["password"])
        address = request.form["address"]
        created_at = now_str()

        existing = Provider.query.filter_by(email=email).first()
        if existing:
            return redirect(url_for("login", role="provider"))

        file = request.files.get("store_image")
        filename = save_uploaded_file(file)

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

        session.permanent = True
        session["user_id"] = new_user.id
        session["role"] = "provider"
        return redirect(url_for("provider_dashboard"))

    return render_template("provider_register.html", category=category)


# ----------------------------
# Beneficiary options + register
# ----------------------------
@app.route("/beneficiary/options")
def beneficiary_options():
    r = redirect_if_logged_in()
    if r and session.get("role") == "beneficiary":
        return r
    return render_template("beneficiary_options.html")


@app.route("/register/beneficiary/<category>", methods=["GET", "POST"])
def register_beneficiary(category):
    if session.get("user_id"):
        return redirect(url_for("beneficiary_dashboard"))

    if request.method == "POST":
        full_name = request.form["full_name"]
        phone = request.form["phone"]
        email = request.form["email"].strip().lower()
        password = generate_password_hash(request.form["password"])
        address = request.form["address"]
        created_at = now_str()

        existing = Beneficiary.query.filter_by(email=email).first()
        if existing:
            return redirect(url_for("login", role="beneficiary"))

        file = request.files.get("document") or request.files.get("beneficiary_image")
        filename = save_uploaded_file(file)

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

        session.permanent = True
        session["user_id"] = new_user.id
        session["role"] = "beneficiary"
        return redirect(url_for("beneficiary_dashboard"))

    return render_template("beneficiary_register.html", category=category)


# ----------------------------
# Login (provider/beneficiary)
# ----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    r = redirect_if_logged_in()
    if r:
        return r

    error = None
    role = request.args.get("role")

    register_link = url_for("choose_role")
    if role == "provider":
        register_link = url_for("provider_options")
    elif role == "beneficiary":
        register_link = url_for("beneficiary_options")

    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        provider = Provider.query.filter_by(email=email).first()
        if provider and check_password_hash(provider.password, password):
            session.permanent = True
            session["user_id"] = provider.id
            session["role"] = "provider"
            return redirect(url_for("provider_dashboard"))

        beneficiary = Beneficiary.query.filter_by(email=email).first()
        if beneficiary and check_password_hash(beneficiary.password, password):
            session.permanent = True
            session["user_id"] = beneficiary.id
            session["role"] = "beneficiary"
            return redirect(url_for("beneficiary_dashboard"))

        error = "Invalid email or password"

    return render_template("login.html", error=error, role=role, register_link=register_link)


# ============================================================
# OWNER (PIN ONLY)
# ============================================================
@app.route("/owner", methods=["GET", "POST"])
def owner_login():
    if session.get("owner"):
        return redirect(url_for("owner_panel"))

    error = None
    if request.method == "POST":
        pin = (request.form.get("pin") or "").strip()

        # ✅ STRICT VALIDATION: digits only + exactly 4
        if (not pin.isdigit()) or (len(pin) != 4):
            error = "PIN must be exactly 4 digits"
        elif pin != OWNER_PIN:
            error = "Wrong PIN"
        else:
            session.permanent = True
            session["owner"] = True
            return redirect(url_for("owner_panel"))

    return render_template("owner_login.html", error=error)


@app.route("/owner/panel")
@owner_required
def owner_panel():
    return render_template("owner_panel.html")


@app.route("/owner/logout")
def owner_logout():
    session.pop("owner", None)
    return redirect(url_for("owner_login"))


# ============================================================
# PROVIDER ROUTES
# ============================================================
@app.route("/provider/dashboard")
@login_required(role="provider")
def provider_dashboard():
    user = Provider.query.get(session["user_id"])

    total_donations = Donation.query.filter_by(provider_id=user.id).count()
    pending_donations = Donation.query.filter_by(provider_id=user.id, status="Pending").count()
    approved_donations = Donation.query.filter_by(provider_id=user.id, status="Approved").count()

    requests_received = (
        db.session.query(Request)
        .join(Donation, Request.donation_id == Donation.id)
        .filter(Donation.provider_id == user.id)
        .count()
    )

    latest_donations = (
        Donation.query
        .filter_by(provider_id=user.id)
        .order_by(Donation.id.desc())
        .limit(6)
        .all()
    )

    rows = (
        db.session.query(Request, Donation, Beneficiary)
        .join(Donation, Request.donation_id == Donation.id)
        .join(Beneficiary, Request.beneficiary_id == Beneficiary.id)
        .filter(Donation.provider_id == user.id)
        .order_by(Request.id.desc())
        .limit(6)
        .all()
    )

    latest_requests = []
    for r, d, b in rows:
        latest_requests.append({
            "beneficiary_name": b.full_name,
            "donation_title": d.title,
            "status": r.status,
            "created_at": r.created_at
        })

    stats = {
        "total_donations": total_donations,
        "pending_donations": pending_donations,
        "approved_donations": approved_donations,
        "total_requests": requests_received
    }

    return render_template(
        "provider_dashboard.html",
        user=user,
        stats=stats,
        latest_donations=latest_donations,
        latest_requests=latest_requests
    )


@app.route("/provider/donation/add", methods=["GET", "POST"])
@login_required(role="provider")
def provider_add_donation():
    user = Provider.query.get(session["user_id"])
    msg = None

    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form.get("description", "").strip()
        quantity = request.form.get("quantity", "").strip()
        category = request.form.get("category", "").strip()

        d = Donation(
            provider_id=user.id,
            title=title,
            description=description,
            quantity=quantity,
            category=category,
            status="Pending",
            created_at=now_str()
        )
        db.session.add(d)
        db.session.commit()
        msg = "Donation saved successfully (Status: Pending)"

    # Use your template file
    return render_template("provider_add_donation.html", user=user, msg=msg)


@app.route("/provider/my-donations")
@login_required(role="provider")
def provider_my_donations():
    user = Provider.query.get(session["user_id"])
    donations = Donation.query.filter_by(provider_id=user.id).order_by(Donation.id.desc()).all()

    if template_exists("provider_my_donations.html"):
        return render_template("provider_my_donations.html", user=user, donations=donations)

    # fallback
    html = "<h2>My Donations</h2><p><a href='/provider/dashboard'>Back</a></p><ul>"
    for d in donations:
        html += f"<li><b>{d.title}</b> - {d.status} - {d.created_at}</li>"
    html += "</ul>"
    return html


@app.route("/provider/requests-received")
@login_required(role="provider")
def provider_requests_received():
    user = Provider.query.get(session["user_id"])

    rows = (
        db.session.query(Request, Donation, Beneficiary)
        .join(Donation, Request.donation_id == Donation.id)
        .join(Beneficiary, Request.beneficiary_id == Beneficiary.id)
        .filter(Donation.provider_id == user.id)
        .order_by(Request.id.desc())
        .all()
    )

    if template_exists("provider_requests_received.html"):
        return render_template("provider_requests_received.html", user=user, rows=rows)

    # fallback
    html = "<h2>Requests Received</h2><p><a href='/provider/dashboard'>Back</a></p><ul>"
    for r, d, b in rows:
        html += f"<li><b>{b.full_name}</b> requested <b>{d.title}</b> - {r.status} - {r.created_at}</li>"
    html += "</ul>"
    return html


@app.route("/provider/reports")
@login_required(role="provider")
def provider_reports():
    user = Provider.query.get(session["user_id"])

    stats = {
        "total": Donation.query.filter_by(provider_id=user.id).count(),
        "pending": Donation.query.filter_by(provider_id=user.id, status="Pending").count(),
        "approved": Donation.query.filter_by(provider_id=user.id, status="Approved").count(),
        "requests": (
            db.session.query(Request)
            .join(Donation, Request.donation_id == Donation.id)
            .filter(Donation.provider_id == user.id)
            .count()
        )
    }

    if template_exists("provider_reports.html"):
        return render_template("provider_reports.html", user=user, stats=stats)

    # fallback
    return f"""
    <h2>Reports / Stats</h2>
    <p><a href="/provider/dashboard">Back</a></p>
    <ul>
      <li>Total Donations: {stats["total"]}</li>
      <li>Pending: {stats["pending"]}</li>
      <li>Approved: {stats["approved"]}</li>
      <li>Requests Received: {stats["requests"]}</li>
    </ul>
    """


@app.route("/provider/profile/edit", methods=["GET", "POST"])
@login_required(role="provider")
def provider_profile_edit():
    user = Provider.query.get(session["user_id"])

    if request.method == "POST":
        user.full_name = request.form.get("full_name", user.full_name)
        user.phone = request.form.get("phone", user.phone)
        user.address = request.form.get("address", user.address)

        file = request.files.get("store_image")
        filename = save_uploaded_file(file)
        if filename:
            user.image = filename

        db.session.commit()
        return redirect(url_for("provider_dashboard"))

    return render_template("provider_edit_profile.html", user=user)


# ============================================================
# BENEFICIARY ROUTES
# ============================================================
@app.route("/beneficiary/dashboard")
@login_required(role="beneficiary")
def beneficiary_dashboard():
    user = Beneficiary.query.get(session["user_id"])

    available_count = Donation.query.filter_by(status="Approved").count()

    my_requests_total = Request.query.filter_by(beneficiary_id=user.id).count()
    my_requests_pending = Request.query.filter_by(beneficiary_id=user.id, status="Pending").count()
    my_requests_approved = Request.query.filter_by(beneficiary_id=user.id, status="Approved").count()
    my_requests_completed = Request.query.filter_by(beneficiary_id=user.id, status="Completed").count()

    latest_available = (
        Donation.query
        .filter_by(status="Approved")
        .order_by(Donation.id.desc())
        .limit(6)
        .all()
    )

    rows = (
        db.session.query(Request, Donation)
        .join(Donation, Request.donation_id == Donation.id)
        .filter(Request.beneficiary_id == user.id)
        .order_by(Request.id.desc())
        .limit(6)
        .all()
    )
    my_latest_requests = []
    for r, d in rows:
        my_latest_requests.append({
            "donation_title": d.title,
            "status": r.status,
            "created_at": r.created_at
        })

    stats = {
        "available_count": available_count,
        "my_requests_total": my_requests_total,
        "my_requests_pending": my_requests_pending,
        "my_requests_approved": my_requests_approved,
        "my_requests_completed": my_requests_completed,
    }

    return render_template(
        "beneficiary_dashboard.html",
        user=user,
        stats=stats,
        latest_available=latest_available,
        my_latest_requests=my_latest_requests
    )


from sqlalchemy import or_

@app.route("/beneficiary/available")
@login_required(role="beneficiary")
def beneficiary_available_donations():
    user = Beneficiary.query.get(session["user_id"])

    q = (request.args.get("q") or "").strip()
    cat = (request.args.get("cat") or "").strip()

    base_query = (
        db.session.query(Donation)
        .join(Provider, Donation.provider_id == Provider.id)
        .filter(Donation.status == "Approved")
        .order_by(Donation.id.desc())
    )

    if q:
        like = f"%{q}%"
        base_query = base_query.filter(
            or_(
                Donation.title.ilike(like),
                Donation.category.ilike(like),
                Provider.full_name.ilike(like),
            )
        )

    if cat:
        base_query = base_query.filter(Donation.category == cat)

    donations = base_query.all()

    categories = (
        db.session.query(Donation.category)
        .filter(Donation.status == "Approved")
        .filter(Donation.category.isnot(None))
        .distinct()
        .order_by(Donation.category.asc())
        .all()
    )
    categories = [c[0] for c in categories if c[0]]

    return render_template(
        "beneficiary_available_donations.html",
        user=user,
        donations=donations,
        categories=categories,
        q=q,
        cat=cat
    )



@app.route("/beneficiary/requests")
@login_required(role="beneficiary")
def beneficiary_requests():
    user = Beneficiary.query.get(session["user_id"])
    rows = (
        db.session.query(Request, Donation)
        .join(Donation, Request.donation_id == Donation.id)
        .filter(Request.beneficiary_id == user.id)
        .order_by(Request.id.desc())
        .all()
    )
    if template_exists("beneficiary_requests.html"):
        return render_template("beneficiary_requests.html", rows=rows, user=user)
    return render_template("success.html", message="Template beneficiary_requests.html not found.")


@app.route("/beneficiary/request/<int:donation_id>", methods=["POST"])
@login_required(role="beneficiary")
def beneficiary_request_donation(donation_id):
    user = Beneficiary.query.get(session["user_id"])
    donation = Donation.query.get(donation_id)

    if not donation or donation.status != "Approved":
        return redirect(url_for("beneficiary_dashboard"))

    existing = Request.query.filter_by(donation_id=donation_id, beneficiary_id=user.id).first()
    if existing:
        return redirect(url_for("beneficiary_dashboard"))

    r = Request(
        donation_id=donation_id,
        beneficiary_id=user.id,
        status="Pending",
        created_at=now_str()
    )
    db.session.add(r)
    db.session.commit()
    return redirect(url_for("beneficiary_dashboard"))


@app.route("/beneficiary/profile/edit", methods=["GET", "POST"])
@login_required(role="beneficiary")
def edit_beneficiary_profile():
    user = Beneficiary.query.get(session["user_id"])

    if request.method == "POST":
        user.full_name = request.form.get("full_name", user.full_name)
        user.phone = request.form.get("phone", user.phone)
        user.address = request.form.get("address", user.address)

        file = request.files.get("document")
        filename = save_uploaded_file(file)
        if filename:
            user.document = filename

        db.session.commit()
        return redirect(url_for("beneficiary_dashboard"))

    return render_template("beneficiary_edit_profile.html", user=user)


# ----------------------------
# Logout (provider/beneficiary)
# ----------------------------
@app.route("/logout")
def logout():
    owner_flag = session.get("owner")
    session.clear()
    if owner_flag:
        session["owner"] = True
    return redirect(url_for("index"))


# ----------------------------
# Run
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)
