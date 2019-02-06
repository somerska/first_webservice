from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from collections import defaultdict
# from sqlalchemy import Enum

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'scoobydoo'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db_sol.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# class Handedness(Enum):
#     left = 0
#     right = 1


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    email = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))
    players = db.relationship('Player', backref='user', lazy=True)
    admin = db.Column(db.Boolean)


class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    rating = db.Column(db.Float)
    handedness = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, first_name, last_name, rating, handedness, user_id):
        self.first_name = first_name
        self.last_name = last_name
        self.rating = rating
        self.handedness = handedness
        self.user_id = user_id

    def serialize(self):
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'rating': self.rating,
            'handedness': self.handedness,
        }


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            bearer_token = request.headers.get('Authorization')
            if not bearer_token:
                return jsonify({'message': 'token is missing'}), 401
            try:
                token_supplied = bearer_token.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'invalid bearer token'}), 401
            data = jwt.decode(token_supplied, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message': 'token is invalid'}), 401
        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/api/user', methods=['POST'])
def create_user():
    data = request.get_json()
    if not all(key in data for key in ('email', 'first_name', 'last_name', 'password', 'confirm_password')):
        return jsonify({'message': 'missing information'}), 401
    if data['password'] != data['confirm_password']:
        return jsonify({'message': 'passwords dont match'}), 401
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'message': 'user already exists'}), 401

    hashed_pw = generate_password_hash(data['password'], method='sha256')
    new_user = User(first_name=data['first_name'],
                    last_name=data['last_name'],
                    email=data['email'],
                    password=hashed_pw,
                    admin=True)
    db.session.add(new_user)
    db.session.commit()

    token = jwt.encode({'token': new_user.id}, app.config['SECRET_KEY'])
    response = defaultdict(dict)
    response['success'], response['user'], response['token'] = True, data, token.decode('utf-8')
    return jsonify(response)


@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'message': 'user does not exist'})
    if check_password_hash(user.password, data['password']):
        token = jwt.encode({'id': user.id,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        response = defaultdict(dict)
        response['success'], response['user'], response['token'] = True, data, token.decode('utf-8')
        return jsonify(response)
    # password was bad
    response = defaultdict(dict)
    response['success'], response['user'], response['token'] = False, data, ''
    return jsonify(response)


@app.route('/api/players', methods=['GET'])
@token_required
def get_players(current_user):
    response = defaultdict(dict)
    response['success'] = True
    response['players'] = [player.serialize() for player in current_user.players]
    return jsonify(response)


@app.route('/api/players', methods=['POST'])
@token_required
def create_player(current_user):
    data = request.get_json()
    if data['first_name'] in current_user.players and data['last_name'] in current_user.players:
        return jsonify({'message': 'first name and last name are not unique'}), 401
    new_player = Player(first_name=data['first_name'],
                        last_name=data['last_name'],
                        rating=data['rating'],
                        handedness=data['handedness'],
                        user_id=current_user.id)
    current_user.players.append(new_player)
    db.session.add(new_player)
    db.session.commit()
    response = defaultdict(dict)
    response['success'] = True
    response['player'] = new_player.serialize()
    return jsonify(response)


@app.route('/api/players/<id>', methods=['DELETE'])
@token_required
def delete_player(current_user, id):
    try:
        user_to_delete = current_user.players[int(id)]
    except IndexError:
        return jsonify({'success': False}), 401
    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(port=3000, debug=True)
