import pytest
import json
from app import app, engine
from utils.jwt_util import generate_access_token, generate_refresh_token


@pytest.fixture()
def client():
    app.config['TESTING'] = True
    client = app.test_client()

    yield client


def test_health_check(client):
    response = client.get("/")
    assert response.status_code == 200
    assert json.loads(response.data) == {"message": "API is up and running"}


def test_signup_post(client):
    response = client.post("/signup", json={
        "username": "testuser",
        "password": "testpassword",
        "pan": "testpan",
        "address": "testaddress",
        "contact": "testcontact",
        "sex": "testsex",
        "nationality": "testnationality",
        "location": "testlocation"
    })
    assert response.status_code == 200
    assert json.loads(response.data) == {"message": "Account created successfully"}


def test_signup_post_existing_username(client):
    response = client.post("/signup", json={
        "username": "testuser",
        "password": "testpassword",
        "pan": "testpan",
        "address": "testaddress",
        "contact": "testcontact",
        "sex": "testsex",
        "nationality": "testnationality",
        "location": "testlocation"
    })
    assert response.status_code == 400
    assert json.loads(response.data) == {"message": "Username exists in the database"}


def test_login_post(client):
    username = "testuser"
    password = "testpassword"

    response = client.post("/login", json={"username": username, "password": password})
    assert response.status_code == 200
    assert "access_token" in json.loads(response.data)
    assert "refresh_token" in json.loads(response.data)


def test_login_post_invalid_credentials(client):
    response = client.post("/login", json={"username": "invaliduser", "password": "invalidpassword"})
    assert response.status_code == 401
    assert json.loads(response.data) == {"message": "username or password is invalid"}


def test_refresh(client):
    refresh_token = generate_refresh_token("testuser")
    response = client.post("/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    assert "access_token" in json.loads(response.data)


def test_refresh_invalid_token(client):
    response = client.post("/refresh", json={"refresh_token": "invalidtoken"})
    assert response.status_code == 401
    assert json.loads(response.data) == {"message": "invalid refresh token"}


def test_credit_endpoint_with_missing_token(client):
    response = client.post("/credit", data=json.dumps({"amount": 100}), content_type="application/json")
    assert response.status_code == 401
    assert response.get_json().get("message") == "Token is missing"


def test_credit_endpoint_with_bad_token(client):
    response = client.post("/credit", data=json.dumps({"token": "invalid_token", "amount": 100}),
                           content_type="application/json")
    assert response.status_code == 401
    assert response.get_json().get("message") == "Invalid token"


def test_credit_endpoint_with_no_amount(client):
    valid_token = generate_access_token("testuser")
    response = client.post("/credit", data=json.dumps({"token": valid_token}), content_type="application/json")
    assert response.status_code == 400
    assert response.get_json().get("message") == "Amount is missing"


def test_credit_endpoint_with_valid_request(client):
    valid_token = generate_access_token("testuser")
    response = client.post("/credit", data=json.dumps({"token": valid_token, "amount": 100}),
                           content_type="application/json")
    assert response.status_code == 200
    assert response.get_json().get("message") == "Successfully credited"
    assert response.get_json().get("balance") == 100


def test_debit_endpoint_with_missing_token(client):
    response = client.post("/debit", data=json.dumps({"amount": 100}), content_type="application/json")
    assert response.status_code == 401
    assert response.get_json().get("message") == "Token is missing"


def test_debit_endpoint_with_bad_token(client):
    response = client.post("/debit", data=json.dumps({"token": "invalid_token", "amount": 100}),
                           content_type="application/json")
    assert response.status_code == 401
    assert response.get_json().get("message") == "Invalid token"


def test_debit_endpoint_with_no_amount(client):
    valid_token = generate_access_token("testuser")
    response = client.post("/debit", data=json.dumps({"token": valid_token}), content_type="application/json")
    assert response.status_code == 400
    assert response.get_json().get("message") == "Amount is missing"


def test_debit_endpoint_with_valid_request(client):
    valid_token = generate_access_token("testuser")
    response = client.post("/debit", data=json.dumps({"token": valid_token, "amount": 100}),
                           content_type="application/json")
    assert response.status_code == 200
    assert response.get_json().get("message") == "Successfully credited"
    assert response.get_json().get("balance") == 0.0


def test_delete_endpoint_with_valid_request(client):
    valid_token = generate_access_token("testuser")
    response = client.delete("/delete", data=json.dumps({"token": valid_token}),
                             content_type="application/json")
    assert response.status_code == 200
    assert response.get_json().get("message") == "Account deleted successfully"


def test_connection_pool_size():
    with app.app_context():
        connection_pool_count = engine.pool.size()
        assert connection_pool_count == 10
