from flask import Flask, render_template, request, redirect, abort, session
from flask_sqlalchemy import SQLAlchemy
import re
import secrets
import bleach  # pip install bleach

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
# ─── SECURITY MEASURE 2: Secret key for CSRF tokens ────────────────────────
app.config['SECRET_KEY'] = secrets.token_hex(32)
db = SQLAlchemy(app)


class FirstApp(db.Model):
    sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"{self.sno} - {self.fname}"


with app.app_context():
    db.create_all()


# ─── SECURITY MEASURE 1: Input Validation ───────────────────────────────────
def validate_name(value: str, field: str):
    """Only allow letters, spaces, hyphens, apostrophes; max 100 chars."""
    if not value or len(value.strip()) == 0:
        return None, f"{field} cannot be empty."
    if len(value) > 100:
        return None, f"{field} must be 100 characters or fewer."
    if not re.match(r"^[A-Za-z\s\-']+$", value):
        return None, f"{field} contains invalid characters."
    return value.strip(), None


def validate_email(value: str):
    """Validate email format and length."""
    if not value or len(value.strip()) == 0:
        return None, "Email cannot be empty."
    if len(value) > 200:
        return None, "Email must be 200 characters or fewer."
    pattern = r'^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+$'
    if not re.match(pattern, value.strip()):
        return None, "Please enter a valid email address."
    return value.strip().lower(), None


# ─── SECURITY MEASURE 2: CSRF Token helpers ─────────────────────────────────
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf(token: str):
    return token and session.get('csrf_token') == token


# Make CSRF token available in all templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token


# ─── SECURITY MEASURE 3: XSS Sanitization helper ────────────────────────────
def sanitize(value: str) -> str:
    """Strip all HTML tags from user input using bleach."""
    return bleach.clean(value, tags=[], strip=True)


@app.route('/', methods=['GET', 'POST'])
def home():
    error = None
    if request.method == 'POST':
        # CSRF check
        if not validate_csrf(request.form.get('csrf_token')):
            abort(403)

        # XSS sanitization (Measure 3)
        raw_fname = sanitize(request.form.get('fname', ''))
        raw_lname = sanitize(request.form.get('lname', ''))
        raw_email = sanitize(request.form.get('email', ''))

        # Input validation (Measure 1)
        fname, err = validate_name(raw_fname, 'First name')
        if err:
            error = err
        if not error:
            lname, err = validate_name(raw_lname, 'Last name')
            if err:
                error = err
        if not error:
            email, err = validate_email(raw_email)
            if err:
                error = err

        if not error:
            entry = FirstApp(fname=fname, lname=lname, email=email)
            db.session.add(entry)
            db.session.commit()
            return redirect('/?added=1')

    allData = FirstApp.query.all()
    return render_template("index.html", allData=allData, error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        # CSRF check
        if not validate_csrf(request.form.get('csrf_token')):
            abort(403)

        raw_fname = sanitize(request.form.get('fname', ''))
        raw_lname = sanitize(request.form.get('lname', ''))
        raw_email = sanitize(request.form.get('email', ''))

        fname, err = validate_name(raw_fname, 'First name')
        if err:
            error = err
        if not error:
            lname, err = validate_name(raw_lname, 'Last name')
            if err:
                error = err
        if not error:
            email, err = validate_email(raw_email)
            if err:
                error = err

        if not error:
            entry = FirstApp(fname=fname, lname=lname, email=email)
            db.session.add(entry)
            db.session.commit()
            return redirect('/?added=1')

    return render_template("register.html", error=error)


@app.route('/update/<int:sno>', methods=['GET', 'POST'])
def update(sno):
    data = FirstApp.query.filter_by(sno=sno).first_or_404()
    error = None

    if request.method == 'POST':
        # CSRF check
        if not validate_csrf(request.form.get('csrf_token')):
            abort(403)

        raw_fname = sanitize(request.form.get('fname', ''))
        raw_lname = sanitize(request.form.get('lname', ''))
        raw_email = sanitize(request.form.get('email', ''))

        fname, err = validate_name(raw_fname, 'First name')
        if err:
            error = err
        if not error:
            lname, err = validate_name(raw_lname, 'Last name')
            if err:
                error = err
        if not error:
            email, err = validate_email(raw_email)
            if err:
                error = err

        if not error:
            data.fname = fname
            data.lname = lname
            data.email = email
            db.session.commit()
            return redirect('/')

    return render_template("update.html", data=data, error=error)


@app.route('/delete/<int:sno>')
def delete(sno):
    data = FirstApp.query.filter_by(sno=sno).first_or_404()
    db.session.delete(data)
    db.session.commit()
    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True)