from flask import Flask, request, render_template, flash
from markupsafe import escape
from datetime import datetime
from decimal import Decimal
from flask_login import login_required, LoginManager, logout_user, login_user, UserMixin, current_user
from flask import redirect, url_for, session
import os
import sys

# Ensure repo root is on sys.path so sibling packages (like Database) can be imported
_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

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
        return redirect(url_for("login"))

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
            elif action == "update_details":
                # redirect to the update user details page
                return redirect(url_for("update_user", username=username))
            elif action == "add_record":
                return redirect(url_for("add_records", username=username))
            elif action == "change_password":
                return redirect(url_for("forgot_password", username=username))
            elif action == "view_records":
                return redirect(url_for("get_records", username=username))

        # Allow passing success/error messages via query params when redirected
        success = request.args.get('success')
        error = request.args.get('error')
        return render_template("user.html", user_details=user, success=success, error=error)
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

        # If user already has profile details set, disallow "add" and redirect to update
        # Consider the profile 'set' if any of these fields are non-null
        details_present = any([
            user.email is not None,
            user.household_size is not None,
            user.location_city is not None,
            user.location_state is not None,
            user.location_postal_code is not None,
            user.location_country is not None,
        ])
        if details_present:
            # Redirect to the update page where edits are allowed
            return redirect(url_for('update_user', username=username, error='Profile already initialized; use Update Details'))

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

        return redirect(url_for('user_page', username=username, skip_check=1))

    except Exception as e:
        db_session.rollback()
        return render_template("add_user_details.html", user=None, error=str(e)), 500
    finally:
        db_session.close()

@app.route("/user/<username>/update_user_details", methods=["GET", "POST"])
@login_required
def update_user(username):
    db_session = Session()
    try:
        user = db_session.query(User).filter(User.user_name == username).first()
        if user is None:
            return render_template("login.html", error="User not found"), 404

        # Authorization: ensure the current user matches requested user
        try:
            if not current_user.is_authenticated or str(current_user.get_id()) != str(user.user_id):
                return render_template("login.html", error="Unauthorized access"), 403
        except Exception:
            return render_template("login.html", error="Unauthorized access"), 403

        # GET -> show the update form pre-populated (also show query-string messages)
        if request.method == 'GET':
            error_msg = request.args.get('error')
            success_msg = request.args.get('success')
            return render_template('update_user_details.html', user=user, error=error_msg, success=success_msg)

        # POST -> apply updates to existing fields
        household_size_raw = request.form.get('household_size')
        if household_size_raw is not None and household_size_raw != '':
            try:
                household_size = int(float(household_size_raw))
            except Exception:
                return render_template('update_user_details.html', user=user, error='household_size must be a number'), 400
            user.household_size = household_size

        # Other optional fields (allow empty string to clear the value)
        city = request.form.get('city')
        state = request.form.get('state')
        zipcode = request.form.get('zipcode')
        country = request.form.get('country')
        email = request.form.get('email')

        if city is not None:
            user.location_city = city or None
        if state is not None:
            user.location_state = state or None
        if zipcode is not None:
            user.location_postal_code = zipcode or None
        if country is not None:
            user.location_country = country or None

        # Email uniqueness check: trim and, if non-empty, ensure no other user has it
        if email is not None:
            email = email.strip() or None
            if email is not None:
                # check for another user with this email
                existing = db_session.query(User).filter(User.email == email, User.user_id != user.user_id).first()
                if existing:
                    return render_template('update_user_details.html', user=user, error='Email already in use'), 400
            user.email = email

        db_session.add(user)
        db_session.commit()

        # Redirect back to the user page with a success message
        return redirect(url_for('user_page', username=username, success='Profile updated'))

    except Exception as e:
        db_session.rollback()
        return render_template('update_user_details.html', user=None, error=str(e)), 500
    finally:
        db_session.close()

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
        if not record_type or not category or not amount_raw or not transaction_date_raw or not payment_method or is_recurring_raw is None:
            return render_template("add_records.html", user=user, error="Missing required fields"), 400

        # Coerce types
        try:
            amount = Decimal(str(amount_raw))
        except Exception:
            return render_template("add_records.html", user=user, error="amount must be numeric"), 400

        # transaction_date: accept dd/mm/YYYY from the form; if ISO given, fallback to parsing that
        transaction_date = None
        if transaction_date_raw:
            parsed = None
            # Try yyyy/mm/dd first, then ISO variants and dd/mm/YYYY
            for fmt in ("%Y/%m/%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y"):
                try:
                    parsed = datetime.strptime(transaction_date_raw, fmt)
                    break
                except Exception:
                    parsed = None
            if parsed is None:
                return render_template("add_records.html", user=user, error="transaction_date must be in yyyy/mm/dd or ISO formats"), 400
            # Normalize to a YYYY/MM/DD string for storage
            transaction_date = parsed.strftime('%Y/%m/%d')

        is_recurring = is_recurring_raw.lower() in ("1", "true", "yes", "on") if isinstance(is_recurring_raw, str) else bool(is_recurring_raw)

        # If the record is recurring, recurrence_interval is required; otherwise default to empty string
        if is_recurring:
            if not recurrence_interval:
                return render_template("add_records.html", user=user, error="recurrence_interval required for recurring records"), 400
        else:
            # ensure recurrence_interval is an empty string (DB non-null constraint)
            recurrence_interval = recurrence_interval or ""

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
        # ensure we always pass `user` into the template to avoid Jinja 'user' undefined errors
        user_for_template = locals().get('user', None)
        return render_template("add_records.html", user=user_for_template, error=str(e)), 500
    finally:
        db_session.close()


@app.route("/user/<username>/update_user_records", methods=["GET", "POST"])
@login_required
def update_records(username):
    db_session = Session()
    try:
        user = db_session.query(User).filter(User.user_name == username).first()
        if user is None:
            return render_template("get_records.html", error="User not found", user=None), 404

        # Authorization: ensure current user matches requested page
        try:
            if not current_user.is_authenticated or str(current_user.get_id()) != str(user.user_id):
                return render_template("login.html", error="Unauthorized access"), 403
        except Exception:
            return render_template("login.html", error="Unauthorized access"), 403

        if request.method == 'GET':
            # Expect ?record_id=NN in query string
            rid = request.args.get('record_id')
            if not rid:
                return render_template('get_records.html', user=user, user_records=db_session.query(Record).filter(Record.user_id==user.user_id).all(), error='No record selected to update')
            try:
                rid_int = int(rid)
            except Exception:
                return render_template('get_records.html', user=user, user_records=db_session.query(Record).filter(Record.user_id==user.user_id).all(), error='Invalid record id')

            record = db_session.query(Record).filter(Record.record_id == rid_int, Record.user_id == user.user_id).first()
            if record is None:
                return render_template('get_records.html', user=user, user_records=db_session.query(Record).filter(Record.user_id==user.user_id).all(), error='Record not found'), 404

            return render_template('update_records.html', user=user, record=record)

        # POST -> apply updates
        record_id = request.form.get('record_id')
        if not record_id:
            return render_template('get_records.html', user=user, user_records=db_session.query(Record).filter(Record.user_id==user.user_id).all(), error='No record id submitted')
        try:
            rid_int = int(record_id)
        except Exception:
            return render_template('update_records.html', user=user, error='Invalid record id'), 400

        record = db_session.query(Record).filter(Record.record_id == rid_int, Record.user_id == user.user_id).first()
        if record is None:
            return render_template('get_records.html', user=user, user_records=db_session.query(Record).filter(Record.user_id==user.user_id).all(), error='Record not found'), 404

        # Gather form fields
        record_type = request.form.get('record_type')
        category = request.form.get('category')
        amount_raw = request.form.get('amount')
        currency = request.form.get('currency')
        transaction_date_raw = request.form.get('transaction_date')
        payment_method = request.form.get('payment_method')
        is_recurring_raw = request.form.get('is_recurring')
        recurrence_interval = request.form.get('recurrence_interval')

        # Basic validation
        if not record_type or not category or not amount_raw or not transaction_date_raw or not payment_method or is_recurring_raw is None:
            return render_template('update_records.html', user=user, record=record, error='Missing required fields'), 400

        # amount
        try:
            amount = Decimal(str(amount_raw))
        except Exception:
            return render_template('update_records.html', user=user, record=record, error='amount must be numeric'), 400

        # transaction_date: accept yyyy/mm/dd first, then several fallbacks
        parsed = None
        for fmt in ("%Y/%m/%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y"):
            try:
                parsed = datetime.strptime(transaction_date_raw, fmt)
                break
            except Exception:
                parsed = None
        if parsed is None:
            return render_template('update_records.html', user=user, record=record, error='transaction_date must be yyyy/mm/dd or ISO formats'), 400
        transaction_date_str = parsed.strftime('%Y/%m/%d')

        is_recurring = is_recurring_raw.lower() in ("1", "true", "yes", "on") if isinstance(is_recurring_raw, str) else bool(is_recurring_raw)

        if is_recurring:
            if not recurrence_interval:
                return render_template('update_records.html', user=user, record=record, error='recurrence_interval required for recurring records'), 400
        else:
            recurrence_interval = recurrence_interval or ""

        # Apply updates
        record.record_type = record_type
        record.category = category
        record.amount = amount
        record.currency = currency
        record.transaction_date = transaction_date_str
        record.payment_method = payment_method
        record.is_recurring = is_recurring
        record.recurrence_interval = recurrence_interval

        db_session.add(record)
        db_session.commit()

        return render_template('update_records.html', user=user, record=record, success='Record updated')

    except Exception as e:
        db_session.rollback()
        user_for_template = locals().get('user', None)
        return render_template('update_records.html', user=user_for_template, error=str(e)), 500
    finally:
        db_session.close()

@app.route("/user/<username>/get_user_records", methods=["GET", "POST"])
@login_required
def get_records(username):
    db_session = Session()
    try:
        # Ensure the requested username exists
        user = db_session.query(User).filter(User.user_name == username).first()
        if user is None:
            return render_template("login.html", error="User not found"), 404

        # Prevent a logged-in user from viewing another user's records
        try:
            if not current_user.is_authenticated or str(current_user.get_id()) != str(user.user_id):
                return render_template("login.html", error="Unauthorized access"), 403
        except Exception:
            return render_template("login.html", error="Unauthorized access"), 403

        user_recs = db_session.query(Record).filter(Record.user_id == user.user_id).all()
        return render_template("get_records.html", user_records=user_recs, user=user)
    except Exception as e:
        db_session.rollback()
        # pass user=None so the template can render safely when user lookup failed
        return render_template("get_records.html", error=str(e), user=None), 500
    finally:
        db_session.close()



@app.route("/user/<username>/get_user_records/filter_user_records", methods=["GET", "POST"])
@login_required
#filter by record_type, category, transaction date, payment_method, is_recurring, recurrence_intervale
def filter_user_records(username):
    db_session = Session()
    try:
        user = db_session.query(User).filter(User.user_name == username).first()
        if user is None:
            return render_template("get_records.html", error="User not found"), 404

        # Authorization: ensure the current user matches the requested user's page
        try:
            if not current_user.is_authenticated or str(current_user.get_id()) != str(user.user_id):
                return render_template("login.html", error="Unauthorized access"), 403
        except Exception:
            return render_template("login.html", error="Unauthorized access"), 403

        # Use GET params by default (the template now submits via GET); support POST fallback
        source = request.args if request.method == "GET" else request.form
        record_filter = source.get("record_type")
        category_filter = source.get("category")
        transaction_date_filter = source.get("transaction_date")
        payment_method_filter = source.get("payment_method")
        is_recurring_filter = source.get("is_recurring")
        recurrence_interval_filter = source.get("recurrence_interval")

        # Build query (do not call .all() until filters applied)
        q = db_session.query(Record).filter(Record.user_id == user.user_id)

        if record_filter:
            q = q.filter(Record.record_type == record_filter)
        if category_filter:
            q = q.filter(Record.category == category_filter)
        if payment_method_filter:
            q = q.filter(Record.payment_method == payment_method_filter)
        if recurrence_interval_filter:
            q = q.filter(Record.recurrence_interval == recurrence_interval_filter)

        # transaction_date: expect dd/mm/YYYY from the select
        if transaction_date_filter:
            try:
                # transaction_date is stored as 'YYYY/MM/DD' string; compare raw string equality
                # validate format first
                _ = datetime.strptime(transaction_date_filter, "%Y/%m/%d")
                q = q.filter(Record.transaction_date == transaction_date_filter)
            except ValueError:
                return render_template("get_records.html", error="transaction_date must be yyyy/mm/dd"), 400

        # is_recurring: accept true/false/1/0
        if is_recurring_filter is not None and is_recurring_filter != "":
            val = str(is_recurring_filter).lower()
            if val in ("true", "1", "yes", "on"):
                q = q.filter(Record.is_recurring == True)
            elif val in ("false", "0", "no", "off"):
                q = q.filter(Record.is_recurring == False)
            else:
                return render_template("get_records.html", error="is_recurring must be true/false"), 400

        user_records = q.order_by(Record.transaction_date.desc()).all()

        # Build distinct lists for dropdowns (prefer server-side lists)
        record_types = [r[0] for r in db_session.query(Record.record_type).filter(Record.user_id == user.user_id).distinct().all()]
        categories = [r[0] for r in db_session.query(Record.category).filter(Record.user_id == user.user_id).distinct().all()]
        payment_methods = [r[0] for r in db_session.query(Record.payment_method).filter(Record.user_id == user.user_id).distinct().all()]
        recurrence_intervals = [r[0] for r in db_session.query(Record.recurrence_interval).filter(Record.user_id == user.user_id).distinct().all()]
        # fetch distinct stored transaction_date strings
        transaction_dates = [r[0] for r in db_session.query(Record.transaction_date).filter(Record.user_id == user.user_id).distinct().all()]

        return render_template(
            "get_records.html",
            user=user,
            user_records=user_records,
            record_types=record_types,
            categories=categories,
            payment_methods=payment_methods,
            recurrence_intervals=recurrence_intervals,
            transaction_dates=transaction_dates
        )
    except Exception as e:
        db_session.rollback()
        return render_template("get_records.html", error=str(e), user=None), 500
    finally:
        db_session.close()

@app.route("/user/<username>/get_user_records/search_records_amount", methods=["GET","POST"])
@login_required
def search_records_amount(username):
    db_session = Session()
    try:
        user = db_session.query(User).filter(User.user_name == username).first()
        if user is None:
            return render_template("login.html", error="User not found"), 404

        try:
            if not current_user.is_authenticated or str(current_user.get_id()) != str(user.user_id):
                return render_template("login.html", error="Unauthorized access"), 403
        except Exception:
            return render_template("login.html", error="Unauthorized access"), 403

        # read inputs (support POST form and GET fallback)
        if request.method == 'POST':
            form = request.form
        else:
            form = request.args

        search_input = form.get("search_query", "").strip()
        min_input = form.get("min_amount", "").strip()
        max_input = form.get("max_amount", "").strip()

        # If no inputs provided, return with a helpful message
        if not search_input and not min_input and not max_input:
            return render_template("get_records.html", error="Provide an exact amount or a min/max range to search", user=user)

        # Helper to normalize and parse Decimal
        def parse_decimal(s):
            if s is None or str(s).strip() == "":
                return None
            ns = str(s).replace(',', '').strip()
            try:
                return Decimal(ns)
            except Exception:
                return None

        # If either min or max provided, perform range search
        if min_input or max_input:
            min_val = parse_decimal(min_input)
            max_val = parse_decimal(max_input)
            if (min_input and min_val is None) or (max_input and max_val is None):
                return render_template("get_records.html", error="Invalid min or max amount format", user=user), 400
            if min_val is not None and max_val is not None and min_val > max_val:
                return render_template("get_records.html", error="min_amount must not be greater than max_amount", user=user), 400

            search_query = db_session.query(Record).filter(Record.user_id == user.user_id)
            if min_val is not None:
                search_query = search_query.filter(Record.amount >= min_val)
            if max_val is not None:
                search_query = search_query.filter(Record.amount <= max_val)
            matched = search_query.order_by(Record.transaction_date.desc()).all()

            return render_template("get_records.html", search_user_records=matched, user=user)

        # Otherwise fall back to exact match on search_query
        if search_input:
            amt = parse_decimal(search_input)
            if amt is None:
                return render_template("get_records.html", error="Invalid amount format", user=user), 400
            matched = db_session.query(Record).filter(Record.user_id == user.user_id, Record.amount == amt).order_by(Record.transaction_date.desc()).all()
            return render_template("get_records.html", search_user_records=matched, user=user)

        # Shouldn't reach here but safe fallback
        return render_template("get_records.html", error="No valid search input provided", user=user)
    except Exception as e:
        db_session.rollback()
        return render_template("get_records.html", error=str(e), user=None), 500
    finally:
        db_session.close()

@app.route("/user/<username>/records/bulk", methods=["POST"])
@login_required
def bulk_action(username):
    db_session = Session()
    try:
        user = db_session.query(User).filter(User.user_name == username).first()
        if user is None:
            return render_template("get_records.html", error="User not found", user=None), 404

        # ensure the current user is allowed to act on this page
        try:
            if not current_user.is_authenticated or str(current_user.get_id()) != str(user.user_id):
                return render_template("login.html", error="Unauthorized access"), 403
        except Exception:
            return render_template("login.html", error="Unauthorized access"), 403

        selected = request.form.getlist('selected')  # list of record_id strings
        action = request.form.get('bulk_action')
        # normalize to ints
        ids = []
        for s in selected:
            try:
                ids.append(int(s))
            except Exception:
                continue

        if not ids:
            return render_template('get_records.html', user=user, user_records=db_session.query(Record).filter(Record.user_id==user.user_id).all(), error='No rows selected')

        if action == 'delete':
            # delete only records that belong to this user
            db_session.query(Record).filter(Record.record_id.in_(ids), Record.user_id == user.user_id).delete(synchronize_session=False)
            db_session.commit()
            return render_template('get_records.html', user=user, user_records=db_session.query(Record).filter(Record.user_id==user.user_id).all(), success=f'Deleted {len(ids)} records')
        elif action == 'update':
            # For update, require exactly one selected row to edit; redirect to update page with record_id
            if len(ids) != 1:
                return render_template('get_records.html', user=user, user_records=db_session.query(Record).filter(Record.user_id==user.user_id).all(), error='Select exactly one record to update')
            rid = ids[0]
            # Redirect to the update route (pass record_id as query param)
            return redirect(url_for('update_records', username=username) + f'?record_id={rid}')
        else:
            return render_template('get_records.html', user=user, user_records=db_session.query(Record).filter(Record.user_id==user.user_id).all(), error='Unknown bulk action')

    except Exception as e:
        db_session.rollback()
        return render_template('get_records.html', user=None, error=str(e)), 500
    finally:
        db_session.close()

if __name__ == "__main__":
    app.run(debug=True)
