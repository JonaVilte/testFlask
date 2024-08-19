import pytest
from flask import g
from flask import session

from flaskr.db import get_db
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

def test_register(client, app):
    # test that viewing the page renders without template errors
    assert client.get("/auth/register").status_code == 200

    # test that successful registration redirects to the login page
    response = client.post("/auth/register", data={"username": "a", "password": "b"})
    assert response.headers["Location"] == "/auth/login"

    # test that the user was inserted into the database
    with app.app_context():
        select = get_db().execute("SELECT * FROM user WHERE username = 'a'").fetchone()

        assert (select is not None)
        #assert(select["password"] == generate_password_hash("b"))
        assert(check_password_hash(select["password"], "b"))        


@pytest.mark.parametrize(
    ("username", "password", "message"),
    (
        ("", "", "Usuario requerido."),
        ("a", "", "Contraseña requerida."),
        ("test", "test", "ya está registrado"),
    ),
)
def test_register_validate_input(client, username, password, message):
    response = client.post(
        "/auth/register", data={"username": username, "password": password}
    )
    assert message in response.data.decode()


def test_login(client, auth):
    # test that viewing the page renders without template errors
    assert client.get("/auth/login").status_code == 200

    # test that successful login redirects to the index page
    response = auth.login()
    assert response.headers["Location"] == "/"

    # login request set the user_id in the session
    # check that the user is loaded from the session
    with client:
        client.get("/")
        assert session["user_id"] == 1
        assert g.user["username"] == "test"


@pytest.mark.parametrize(
    ("username", "password", "message"),
    (("a", "test", "Usuario y contraseña incorrecta."), 
     ("test", "12354565", "Usuario y contraseña incorrecta.")),
)
def test_login_validate_input(auth, username, password, message):
    response = auth.login(username, password)
    assert message in response.data.decode()


def test_logout(client, auth):
    auth.login()

    with client:
        auth.logout()
        assert "user_id" not in session
