import hashlib

from flask import request
from flask_restx import Resource, Namespace
from application.setup_db import db
from application.models import User, UserSchema
from auth import auth_required, admin_required

user_ns = Namespace('users')


@user_ns.route('/')
class UsersView(Resource):
    @auth_required
    def get(self):
        users = db.session.query(User).all()
        us_all = UserSchema(many=True).dump(users)

        return us_all, 200

    @auth_required
    def post(self):
        req_json = request.json
        ent = User(**req_json)

        db.session.add(ent)
        db.session.commit()
        return "", 201, {"location": f"/movies/{ent.id}"}

    def get_hash(self):
        return hashlib.md5(self.password.encode('utf-8')).hexdigest()


@user_ns.route('/<int:uid>')
class UserView(Resource):
    @auth_required
    def get(self, uid):
        b = db.session.query(User).get(uid)
        sm_d = UserSchema().dump(b)
        return sm_d, 200

    @admin_required
    def put(self, uid):
        user = db.session.query(User).get(uid)
        req_json = request.json
        user.username = req_json.get("username")
        user.password = req_json.get("password")
        user.role = req_json.get("role")
        db.session.add(user)
        db.session.commit()
        return "", 204

    @admin_required
    def delete(self, uid):
        user = db.session.query(User).get(uid)

        db.session.delete(user)
        db.session.commit()
        return "", 204