#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

user_schema = UserSchema(exclude=('recipes',))
recipe_schema = RecipeSchema()


def current_user():
    """Return the logged-in user, or None."""
    user_id = session.get('user_id')
    return db.session.get(User, user_id) if user_id else None


class Signup(Resource):
    def post(self):
        data = request.get_json() or {}

        try:
            user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio'),
            )
            password = data.get('password')
            if not password:
                raise ValueError('Password must be present.')
            user.password_hash = password

            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['Username must be present and unique.']}, 422
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

        session['user_id'] = user.id
        return user_schema.dump(user), 201


class CheckSession(Resource):
    def get(self):
        user = current_user()
        if not user:
            return {'error': 'Unauthorized'}, 401
        return user_schema.dump(user), 200


class Login(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter(User.username == username).first()
        if user and password and user.authenticate(password):
            session['user_id'] = user.id
            return user_schema.dump(user), 200

        return {'error': 'Invalid username or password'}, 401


class Logout(Resource):
    def delete(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
        session['user_id'] = None
        return {}, 204


class RecipeIndex(Resource):
    def get(self):
        if not current_user():
            return {'error': 'Unauthorized'}, 401
        recipes = Recipe.query.all()
        return [recipe_schema.dump(r) for r in recipes], 200

    def post(self):
        user = current_user()
        if not user:
            return {'error': 'Unauthorized'}, 401

        data = request.get_json() or {}

        try:
            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user=user,
            )
            db.session.add(recipe)
            db.session.commit()
        except (IntegrityError, ValueError) as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

        return recipe_schema.dump(recipe), 201


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
