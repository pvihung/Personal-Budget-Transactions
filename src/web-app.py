from flask import Flask, request, render_template, flash
from markupsafe import escape
from datetime import datetime
from decimal import Decimal
from flask_login import login_required, LoginManager, logout_user, login_user, UserMixin, current_user
from flask import redirect, url_for, session
import os

from Database.database import Session, Record, User

__author__ = 'Syed Zain'
__version__ = '1.0'


app = Flask(__name__)
# Required for session cookies used by Flask and Flask-Login. Change in production.
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Small adapter so flask-login can work with the ORM User model
class FlaskUser(UserMixin):
    def __init__(self, orm_user):
        self._orm = orm_user

    def get_id(self):
        # flask-login requires a str id
        return str(self._orm.user_id)

    def __getattr__(self, name):
        # delegate attribute access to the underlying ORM object
        return getattr(self._orm, name)


@login_manager.user_loader
def load_user(user_id):
    db_session = Session()
    try:
        try:
            uid = int(user_id)
        except Exception:
            return None
        orm_user = db_session.query(User).filter(User.user_id == uid).first()
        return FlaskUser(orm_user) if orm_user else None
    finally:
        db_session.close()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login/forgot_password/<username>", methods=["POST", "GET"])
@login_required
def forgot_password(username):
    db_session = Session()
    try:
        # GET -> show reset form
        if request.method == "GET":
            return render_template("forgot_password.html", user=escape(username))

        # POST -> change password
        user = db_session.query(User).filter(User.user_name == username).first()
        if user is None:
            return render_template("forgot_password.html", error="User not found"), 404

        # use request.form.get correctly
        new_password = request.form.get('password')
        if not new_password:
            return render_template("forgot_password.html", user=escape(username), error="Password is required"), 400

        user.password = new_password
        db_session.add(user)
        db_session.commit()
        return redirect(url_for("login"))#, success=f"Password updated for {escape(username)}", user=escape(username))

    except Exception as e:
        db_session.rollback()
        return render_template("forgot_password.html", error=str(e)), 500
    finally:
        db_session.close()


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    db_session = Session()
    try:
        # GET -> show signup form
        if request.method == 'GET':
            return render_template("signup.html")

        # POST -> create user
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        # Basic validation
        if not username or not password:
            return render_template("signup.html", error="Username and password are required"), 400

        # Check for existing username
        existing_user = db_session.query(User).filter(User.user_name == username).first()
        if existing_user:
            return render_template("signup.html", error="Username already exists"), 400

        # Optional: check for existing email
        if email:
            existing_email = db_session.query(User).filter(User.email == email).first()
            if existing_email:
                return render_template("signup.html", error="Email already in use"), 400

        # Store the password as provided (no hashing)
        new_user = User(user_name=username, password=password, email=email)
        db_session.add(new_user)
        db_session.commit()
        return redirect(url_for("login"))#, success="Account created successfully for {}".format(escape(username)))

    except Exception as e:
        db_session.rollback()
        return render_template("signup.html", error=str(e)), 500
    finally:
        db_session.close()

@app.route("/login", methods=["GET", "POST"])
def login():
    # Use DB to verify credentials when POST
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        db_session = Session()
        try:
            user = db_session.query(User).filter(User.user_name == username).first()
            if not user:
                return render_template("login.html", error="Invalid username or password"), 401
            # Direct password comparison (no hashing)
            if user.password != password:
                return render_template("login.html", error="Invalid username or password"), 401
            # mark the user as authenticated with flask-login
            login_user(FlaskUser(user))
            # optionally store username in session for templates or quick access
            session['username'] = username
            return redirect(url_for("user_page", username=username))
        except Exception as e:
            return render_template("login.html", error=str(e)), 500
        finally:
            db_session.close()
    else:

        return render_template('login.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    flash("You have been logged out.")
    return redirect(url_for("index"))

@app.route("/login/user/<username>", methods=["GET", "POST"])
@login_required
def user_page(username):

    db_session = Session()
    try:
        user = db_session.query(User).filter(User.user_name == username).first()
        if user is None:
            # Return the login page with an error if the user doesn't exist
            return render_template("login.html", error="User not found"), 404
        # Ensure the currently authenticated user matches the requested user page
        # This prevents a logged-in user from viewing another user's page by URL tampering
        try:
            if current_user.is_authenticated and str(current_user.get_id()) != str(user.user_id):
                return render_template("login.html", error="Unauthorized access"), 403
        except Exception:
            # If current_user mishandles get_id for any reason, deny access safely
            return render_template("login.html", error="Unauthorized access"), 403

        # If the user submitted the form, handle the button pressed.
        if request.method == "POST":
            action = request.form.get("action_button")
            if action == "logout":
                return redirect(url_for("logout"))
            elif action == "edit_data":
                # redirect to add_user_details for this user
                return redirect(url_for("add_user_details", username=username))
            elif action == "add_record":
                return redirect(url_for("add_records", username=username))
            elif action == "change_password":
                return redirect(url_for("forgot_password", username=username))

        return render_template("user.html", user_details=user)
    except Exception as e:
        return render_template("login.html", error=str(e)), 500
    finally:
        db_session.close()

@app.route("/user/<username>/add", methods=["GET", "POST"])
@login_required
def add_user_details(username):
    db_session = Session()
    try:
        # Load user once (or return 404 if not found)
        user = db_session.query(User).filter(User.user_name == username).first()
        if user is None:
            return render_template("add_user_details.html", error="User not found"), 404

        # GET -> show form populated with current values
        if request.method == 'GET':
            return render_template("add_user_details.html", user=user)

        # POST -> update provided fields only
        household_size_raw = request.form.get("household_size")
        household_size = None
        if household_size_raw:
            try:
                # accept ints or floats but store as int
                household_size = int(float(household_size_raw))
            except ValueError:
                return render_template("add_user_details.html", user=user, error="household_size must be a number"), 400

        city = request.form.get("city")
        state = request.form.get("state")
        zipcode = request.form.get("zipcode")
        country = request.form.get("country")

        # Update only when values are provided (allow empty string to clear if desired)
        if household_size is not None:
            user.household_size = household_size
        if city is not None:
            user.location_city = city or None
        if state is not None:
            user.location_state = state or None
        if zipcode is not None:
            user.location_postal_code = zipcode or None
        if country is not None:
            user.location_country = country or None

        # user is already tracked by the session; add() is optional but harmless
        db_session.add(user)
        db_session.commit()

        # After saving, always redirect back to the user page but include skip_check=1
        # so user_page won't redirect back to this form immediately (avoids loop).
        return redirect(url_for('user_page', username=username, skip_check=1))

    except Exception as e:
        db_session.rollback()
        return render_template("add_user_details.html", user=None, error=str(e)), 500
    finally:
        db_session.close()

@app.route("/user/<username>/update_user_details", methods=["GET", "POST"])
@login_required
def update_user():
    pass

# changed route to avoid collision with add_user_details
@app.route("/user/<username>/records", methods=["GET", "POST"])
@login_required
def add_records(username):
    db_session = Session()
    try:
        user = db_session.query(User).filter(User.user_name == username).first()

        if user is None:
            return render_template("add_records.html", error="User not found"), 404
        if request.method == 'GET':
            return render_template("add_records.html", user=user)

        # POST -> create a Record for this user
        record_type = request.form.get("record_type")
        category = request.form.get("category")
        amount_raw = request.form.get("amount")
        currency = request.form.get("currency")
        transaction_date_raw = request.form.get("transaction_date")
        payment_method = request.form.get("payment_method")
        is_recurring_raw = request.form.get("is_recurring")
        recurrence_interval = request.form.get("recurrence_interval")

        # Basic validation
        if not record_type or not category or not amount_raw or not transaction_date_raw or not payment_method or is_recurring_raw is None or recurrence_interval is None:
            return render_template("add_records.html", user=user, error="Missing required fields"), 400

        # Coerce types
        try:
            amount = Decimal(str(amount_raw))
        except Exception:
            return render_template("add_records.html", user=user, error="amount must be numeric"), 400

        try:
            transaction_date = datetime.fromisoformat(transaction_date_raw)
        except Exception:
            return render_template("add_records.html", user=user, error="transaction_date must be ISO-8601 string"), 400

        is_recurring = is_recurring_raw.lower() in ("1", "true", "yes", "on") if isinstance(is_recurring_raw, str) else bool(is_recurring_raw)

        record = Record(
            user_id=user.user_id,
            record_type=record_type,
            category=category,
            amount=amount,
            currency=currency,
            transaction_date=transaction_date,
            payment_method=payment_method,
            is_recurring=is_recurring,
            recurrence_interval=recurrence_interval,
        )
        db_session.add(record)
        db_session.commit()
        return render_template("add_records.html", user=user, success="Record added", record=record)

    except Exception as e:
        db_session.rollback()
        return render_template("add_records.html", error=str(e)), 500
    finally:
        db_session.close()

@app.route("/user/<username>/delete_user_records", methods=["GET", "POST"])
@login_required
def delete_records():
    pass

@app.route("/user/<username>/update_user_records", methods=["GET", "POST"])
@login_required
def update_records():
    pass

@app.route("/get_user_records", methods=["GET", "POST"])
def get_records():
    pass


@app.route("/get_transactions", methods=["GET", "POST"])
def get_transactions():
    pass

"""
@app.route("/transactions", methods=["GET", "POST"])
def transactions():
    session = Session()
    try:
        if request.method == "GET":
            # return first 100 records as JSON
            records = session.query(Record).limit(100).all()
            def serialize(r):
                return {
                    "record_id": r.record_id,
                    "user_id": r.user_id,
                    "record_type": r.record_type,
                    "category": r.category,
                    "amount": float(r.amount) if r.amount is not None else None,
                    "currency": r.currency,
                    "transaction_date": r.transaction_date.isoformat() if r.transaction_date else None,
                    "payment_method": r.payment_method,
                    "is_recurring": bool(r.is_recurring) if r.is_recurring is not None else None,
                    "recurrence_interval": r.recurrence_interval,
                }
            data = [serialize(r) for r in records]
            return jsonify(data)

        # POST - create a new record
        payload = request.get_json(force=True)
        required = ["user_id", "record_type", "category", "amount", "transaction_date", "payment_method", "is_recurring", "recurrence_interval"]
        missing = [f for f in required if f not in payload]
        if missing:
            return jsonify({"error": "missing fields", "missing": missing}), 400

        # Ensure the referenced user exists to avoid FK constraint errors
        user = session.get(User, payload.get('user_id'))
        if user is None:
            return jsonify({"error": "user_id does not exist"}), 400

        # Parse and coerce types
        try:
            payload['transaction_date'] = datetime.fromisoformat(payload['transaction_date'])
        except Exception:
            return jsonify({"error": "transaction_date must be ISO-8601 string"}), 400
        try:
            payload['amount'] = Decimal(str(payload['amount']))
        except Exception:
            return jsonify({"error": "amount must be numeric"}), 400
        payload['is_recurring'] = bool(payload.get('is_recurring'))

        record = Record(**payload)
        session.add(record)
        session.commit()
        return jsonify({"record_id": record.record_id}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()
"""
if __name__ == "__main__":
    app.run(debug=True)
