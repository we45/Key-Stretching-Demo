from flask import Flask, render_template
from pbkdf2 import pbkdf2_hex
from flask_bcrypt import bcrypt, generate_password_hash
import time
import hashlib
from random import randint, choice
from argon2 import PasswordHasher
from os import urandom

app = Flask(__name__)


def generate_password():
    pass_chars = 'abcdefghijkmnopqrstuvwxyz123456789ABCDEFGHJKLMNPQRSTUVWXYZ'
    password = ''.join([str(''.join(str(choice(pass_chars))))
                        for c in range(12)])
    return password


@app.route('/sha256', methods=['GET'])
def generate_sha1_hash():
    pwd = generate_password()
    start_time = time.clock()
    sha_hash = hashlib.sha256(pwd).hexdigest()
    time_taken = time.clock() - start_time
    return render_template('index.html', hash_type="Raw SHA-256", password=pwd,
                           hash=sha_hash, duration=time_taken)


@app.route('/pbkdf2', methods=["GET"])
def generate_pbkdf2_hash():
    pwd = generate_password()
    start_time = time.clock()
    salt = urandom(16)
    sha_hash = pbkdf2_hex(pwd, salt, iterations=10000, hashfunc=hashlib.sha256)
    time_taken = time.clock() - start_time
    return render_template('index.html', hash_type="PBKDF2-SHA256",
                           password=pwd, hash=sha_hash, duration=time_taken)


@app.route('/bcrypt', methods=["GET"])
def generate_bcrypt_hash():
    pwd = generate_password()
    start_time = time.clock()
    hash = generate_password_hash(pwd, 12)
    time_taken = time.clock() - start_time
    return render_template('index.html', hash_type="BCrypt",
                           password=pwd, hash=hash, duration=time_taken)
                           

@app.route('/argon2', methods=["GET"])
def generate_argon2_hash():
    pwd = generate_password()
    start_time = time.clock()
    hash = PasswordHasher().hash(pwd)
    time_taken = time.clock() - start_time
    return render_template('index.html', hash_type="Argon2",
                           password=pwd, hash=hash, duration=time_taken)


if __name__ == "__main__":
    app.run(debug=True)
