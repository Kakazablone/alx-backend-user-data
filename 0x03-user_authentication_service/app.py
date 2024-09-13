#!/usr/bin/env python3
"""API Routes for Authentication Service"""

from typing import Optional, Tuple, Union
from auth import Auth
from flask import Flask, jsonify, request, abort, redirect
from flask import Response, make_response

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def hello_world() -> Response:
    """ Base route for authentication service API """
    msg = {"message": "Bienvenue"}
    return jsonify(msg)


@app.route('/users', methods=['POST'])
def register_user() -> Union[Response, Tuple[Response, int]]:
    """Registers a new user if it does not exist before"""
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        abort(400)

    try:
        AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400

    msg = {"email": email, "message": "user created"}
    return jsonify(msg)


@app.route('/sessions', methods=['POST'])
def log_in() -> Response:
    """Logs in a user and returns session ID"""
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        abort(400)

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    response = make_response(jsonify({"email": email, "message": "logged in"}))
    response.set_cookie("session_id", session_id)
    return response


@app.route('/sessions', methods=['DELETE'])
def log_out() -> Response:
    """Finds the user by session ID and logs them out"""
    session_id = request.cookies.get("session_id")

    if not session_id:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)

    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'])
def profile() -> Union[Response, Tuple[Response, int]]:
    """Returns the user's profile based on session ID"""
    session_id = request.cookies.get("session_id")

    if not session_id:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)

    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST'])
def reset_password() -> Union[Response, Tuple[Response, int]]:
    """Generates a reset password token"""
    email = request.form.get('email')

    if not email:
        abort(403)

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route('/reset_password', methods=['PUT'])
def update_password() -> Union[Response, Tuple[Response, int]]:
    """Updates the user's password using the reset token"""
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    if not email or not reset_token or not new_password:
        abort(400)

    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
