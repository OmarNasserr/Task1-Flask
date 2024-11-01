import binascii
from datetime import timedelta
import werkzeug.exceptions
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

app = Flask(__name__)
secret_key = 'EjivmkDbiM2-TEpXlt5HfPYr3n0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///books.db'
app.config['JWT_SECRET_KEY'] = secret_key
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
expiration_time = 15

# In-memory blocklist to store logged out tokens
revoked_tokens = set()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    author = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(250))


@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(username=data['username'], password=hashed_password)
        db.session.add(user)
        db.session.commit()
        token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=expiration_time))
        return jsonify({"message": "User registered successfully.",
                        "id": encrypt_id(user.id),
                        "username": user.username,
                        "token": token}), 201
    except werkzeug.exceptions.BadRequest:
        return jsonify({"message": "Invalid JSON data or incorrect format."}), 400
    except IntegrityError:
        return jsonify({"message": "username already exists."}), 400
    except Exception as e:
        return jsonify({"Error": f"{e}"}), 400


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and bcrypt.check_password_hash(user.password, data['password']):
            token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=expiration_time))
            return jsonify({"message": "Logged in successfully.",
                            "id": encrypt_id(user.id),
                            "username": user.username,
                            "token": token}), 200
        return jsonify({"message": "Invalid username or password."}), 401
    except werkzeug.exceptions.BadRequest:
        return jsonify({"message": "Invalid JSON data or incorrect format."}), 400
    except Exception as e:
        return jsonify({"Error": f"{e}"}), 400


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    revoked_tokens.add(jti)  # Add it to the blocklist
    return jsonify({"message": "Logged out successfully."}), 200


# Callback function to check if a token is revoked
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in revoked_tokens


@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    books = Book.query.all()
    return jsonify([
        {
            "id": encrypt_id(book.id),
            "title": book.title,
            "author": book.author,
            "description": book.description
        } for book in books]), 200


@app.route('/books', methods=['POST'])
@jwt_required()
def add_book():
    try:
        data = request.get_json()
        book = Book(title=data['title'], author=data['author'], description=data.get('description', ''))
        db.session.add(book)
        db.session.commit()
        return jsonify({"message": "Book added successfully.",
                        "id": encrypt_id(book.id),
                        "title": book.title,
                        "author": book.author,
                        "description": book.description}), 201
    except werkzeug.exceptions.BadRequest:
        return jsonify({"message": "Invalid JSON data or incorrect format."}), 400
    except KeyError as e:
        return jsonify({"message": f"Missing field in JSON data: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"Error": f"{e}"}), 400


@app.route('/books/<string:encrypted_id>', methods=['GET'])
@jwt_required()
def get_book(encrypted_id):
    try:
        book_id = decrypt_id(encrypted_id)
        book = Book.query.get(book_id)
        if book:
            return jsonify(
                {"id": encrypted_id, "title": book.title, "author": book.author, "description": book.description}), 200
        return jsonify({"message": "Book not found."}), 404
    except binascii.Error as e:
        return jsonify({"message": f"Book not found."}), 404
    except Exception as e:
        return jsonify({"Error": f"{e}"}), 400


@app.route('/books/<string:encrypted_id>', methods=['PUT'])
@jwt_required()
def update_book(encrypted_id):
    try:
        data = request.get_json()
        book_id = decrypt_id(encrypted_id)
        book = Book.query.get(book_id)
        if not data:
            return jsonify({"message": "Please provide data to update the item."}), 400
        if book:
            book.title = data.get('title', book.title)
            book.author = data.get('author', book.author)
            book.description = data.get('description', book.description)
            db.session.commit()
            return jsonify({
                "message": "Book updated successfully.",
                "id": encrypted_id,
                "title": book.title,
                "author": book.author,
                "description": book.description
            }), 200
        return jsonify({"message": "Book not found."}), 404
    except werkzeug.exceptions.BadRequest:
        return jsonify({"message": "Invalid JSON data or incorrect format."}), 400
    except KeyError as e:
        return jsonify({"message": f"Missing field in JSON data: {str(e)}"}), 400
    except binascii.Error as e:
        return jsonify({"message": f"Book not found."}), 404
    except Exception as e:
        return jsonify({"Error": f"{e}"}), 400


@app.route('/books/<string:encrypted_id>', methods=['DELETE'])
@jwt_required()
def delete_book(encrypted_id):
    try:
        book_id = decrypt_id(encrypted_id)
        book = Book.query.get(book_id)
        if book:
            db.session.delete(book)
            db.session.commit()
            return jsonify({"message": "Book was deleted successfully."}), 200
        return jsonify({"message": "Book not found."}), 404
    except binascii.Error:
        return jsonify({"message": "Book not found."}), 404
    except Exception as e:
        return jsonify({"Error": f"{e}"}), 400


def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_id(id, password=secret_key):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_id = encryptor.update(str(id).encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(salt + iv + encryptor.tag + encrypted_id).decode()


def decrypt_id(encrypted_id: str, password=secret_key):
    decoded_data = base64.urlsafe_b64decode(encrypted_id)
    salt, iv, tag, encrypted_id_bytes = decoded_data[:16], decoded_data[16:28], decoded_data[28:44], decoded_data[44:]
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return int(decryptor.update(encrypted_id_bytes) + decryptor.finalize())


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
