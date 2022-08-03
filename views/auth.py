import calendar
import datetime
import hashlib

import jwt
from flask import request
from flask_restx import Resource, Namespace, abort
from application.setup_db import db
from application.models import User
from application.config import Config

auth_ns = Namespace('auth')


@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        # Авторизация нового пользователя
        req_json = request.json
        username = req_json.get("username", None)
        password = req_json.get("password", None)
        if None in [username, password]:
            abort(400)

        user = db.session.query(User).filter(User.username == username).first()

        if user is None:
            return {"error": "Неверные учётные данные"}, 401

        password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()

        if password_hash != user.password:
            return {"error": "Неверные учётные данные"}, 401

        data = {
            "username": user.username,
            "role": user.role
        }
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, Config.SECRET_HERE, algorithm=Config.ALGO)
        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, Config.SECRET_HERE, algorithm=Config.ALGO)
        tokens = {"access_token": access_token, "refresh_token": refresh_token}

        return tokens, 201

    def put(self):
        # Обновление токена
        req_json = request.json
        refresh_token = req_json.get("refresh_token")
        if refresh_token is None:
            abort(400)

        try:
            data = jwt.decode(jwt=refresh_token, key=Config.SECRET_HERE, algorithms=Config.ALGO)
        except Exception as e:
            abort(400)

        username = data.get("username")

        user = db.session.query(User).filter(User.username == username).first()

        data = {
            "username": user.username,
            "role": user.role
        }
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, Config.SECRET_HERE, algorithm=Config.ALGO)
        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, Config.SECRET_HERE, algorithm=Config.ALGO)
        tokens = {"access_token": access_token, "refresh_token": refresh_token}

        return tokens, 201


def admin_required(func):
    # Проверка роли админ/пользователь
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)
        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]
        try:
            user = jwt.decode(token, Config.SECRET_HERE, algorithms=[Config.ALGO])
            role = user.get("role")
        except Exception as e:
            print("JWT Decode Exception", e)
            abort(401)
        if role != "admin":
            abort(403)
        return func(*args, **kwargs)

    return wrapper


def auth_required(func):
    # Проверка авторизован ли пользователь
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]
        try:
            jwt.decode(token, Config.SECRET_HERE, algorithms=[Config.ALGO])
        except Exception as e:
            print("JWT Decode Exception", e)
            abort(401)
        return func(*args, **kwargs)

    return wrapper
