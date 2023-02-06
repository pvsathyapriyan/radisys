from flask import jsonify, request, render_template, send_from_directory
from app import app, session
from app.models import User, Account
import bcrypt  # for encrypting passwords
from utils.jwt_util import generate_access_token, generate_refresh_token, verify_access_token, \
    verify_refresh_token, invalidate_access_token


@app.route("/")
def health_check():
    return jsonify({"message": "API is up and running"})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.json.get("username")
        password = request.json.get("password")

        # checking if user exists in db
        try:
            user = session.query(User).filter_by(username=username).first()
            password_hash_in_db = user.password
        except AttributeError:
            return jsonify({"message": "username or password is invalid"}), 401

        # checking if the credentials are right
        if user and bcrypt.checkpw(password.encode("utf-8"), password_hash_in_db.encode("utf-8")):
            access_token = generate_access_token(request.json.get('username'))
            refresh_token = generate_refresh_token(request.json.get('username'))
            return jsonify({"message": "successful", "access_token": access_token, "refresh_token": refresh_token})
        else:
            return jsonify({"message": "username or password is invalid"}), 401


@app.route('/refresh', methods=['POST'])
def refresh():

    if request.method == "POST":
        refresh_token = request.json.get("refresh_token")
        username = verify_refresh_token(refresh_token)

        if username:
            access_token = generate_access_token(username)
            return jsonify({"message": "successful", "access_token": access_token})
        else:
            return jsonify({"message": "invalid refresh token"}), 401


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.json.get("username")

        # checking if username is existing in db
        user = session.query(User).filter_by(username=username).first()
        if user:
            return jsonify({"message": "Username exists in the database"}), 400
        else:
            password = request.json.get("password").encode("utf-8")
            password_hash = bcrypt.hashpw(password, bcrypt.gensalt())

            pan = request.json.get("pan")
            address = request.json.get("address")
            contact = request.json.get("contact")
            sex = request.json.get("sex")
            nationality = request.json.get("nationality")
            location = request.json.get("location")

            user = User(username=username, password=password_hash, location=location, pan=pan, address=address,
                        contact=contact, sex=sex, nationality=nationality)
            session.add(user)
            session.commit()

            user_id = session.query(User).with_entities(User.id).filter_by(username=username).first()[0]
            account = Account(user_id=user_id, amount=0)
            session.add(account)
            session.commit()

            return jsonify({"message": "Account created successfully"})


@app.route("/update", methods=["PUT"])
def update_user():
    token = request.json.get("token")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    username = verify_access_token(token)
    if not username:
        return jsonify({"message": "Invalid token"}), 401

    username = request.json.get("username")
    user = session.query(User).filter_by(username=username).first()
    if not user:
        return jsonify({"message": "Username does not exist in the database"}), 400
    else:
        password = request.json.get("password", None)
        if password:
            password = password.encode("utf-8")
            password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
            user.password = password_hash

        pan = request.json.get("pan", None)
        if pan:
            user.pan = pan

        address = request.json.get("address", None)
        if address:
            user.address = address

        contact = request.json.get("contact", None)
        if contact:
            user.contact = contact

        sex = request.json.get("sex", None)
        if sex:
            user.sex = sex

        nationality = request.json.get("nationality", None)
        if nationality:
            user.nationality = nationality

        location = request.json.get("location", None)
        if location:
            user.location = location

        session.commit()
        return jsonify({"message": "User updated successfully"})


@app.route("/delete", methods=["DELETE"])
def delete_account():
    token = request.json.get("token")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    username = verify_access_token(token)
    if not username:
        return jsonify({"message": "Invalid token"}), 401

    # check if the user is in the database
    user = session.query(User).filter_by(username=username).first()
    if not user:
        return jsonify({"message": "Username does not exist in the database"}), 400
    else:
        account = session.query(Account).filter_by(user_id=user.id).first()
        session.delete(account)
        session.delete(user)
        session.commit()
        return jsonify({"message": "Account deleted successfully"})


@app.route("/credit", methods=["POST"])
def credit():
    token = request.json.get("token")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    username = verify_access_token(token)
    if not username:
        return jsonify({"message": "Invalid token"}), 401

    # check if the user is in the database
    user = session.query(User).filter_by(username=username).first()
    if not user:
        return jsonify({"message": "Username does not exist"}), 400
    else:
        user_id = user.id

    amount = request.json.get("amount")
    if not amount:
        return jsonify({"message": "Amount is missing"}), 400

    # update the balance for the user
    account = session.query(Account).filter(Account.user_id == user_id).first()
    new_balance = account.amount + amount
    account.amount = new_balance
    session.commit()

    return jsonify({"message": "Successfully credited", "balance": new_balance})


@app.route("/debit", methods=["POST"])
def debit():
    token = request.json.get("token")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    username = verify_access_token(token)
    if not username:
        return jsonify({"message": "Invalid token"}), 401

    # check if the user is in the database
    user = session.query(User).filter_by(username=username).first()
    if not user:
        return jsonify({"message": "Username does not exist"}), 400
    else:
        user_id = user.id

    amount = request.json.get("amount")
    if not amount:
        return jsonify({"message": "Amount is missing"}), 400

    # update the balance for the user
    account = session.query(Account).filter(Account.user_id == user_id).first()
    new_balance = account.amount - amount
    account.amount = new_balance
    session.commit()

    return jsonify({"message": "Successfully credited", "balance": new_balance})


@app.route('/logout', methods=['POST'])
def logout():

    if request.method == "POST":
        access_token = request.json.get("access_token")
        username = verify_access_token(access_token)

        if username:
            invalidate_access_token(access_token, username)
            return jsonify({"message": "logout successful"})
        else:
            return jsonify({"message": "Invalid token"}), 401


@app.route('/docs')
def swagger_ui():
    return render_template('swagger_ui.html')


@app.route('/spec')
def get_spec():
    return send_from_directory(app.root_path, 'openapi.yaml')
