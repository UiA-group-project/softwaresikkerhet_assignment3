from datetime import datetime
import json
from cryptography.fernet import Fernet
from config import Config
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin

cipher_suite = Fernet(Config.FERNET_SECRET_KEY)

db = SQLAlchemy()


class Session(OAuthConsumerMixin, db.Model):
    __tablename__ = 'sessions'

    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String, nullable=False)
    _token = db.Column("token", db.String, unique=True, nullable=False)  # Store token as JSON
    created_at = db.Column(db.DateTime, default=datetime.now)

    @property
    def token(self):
        # Decrypt and deserialize the token JSON string
        decrypted_token = cipher_suite.decrypt(self._token.encode('utf-8')).decode('utf-8')
        return json.loads(decrypted_token)

    @token.setter
    def token(self, value):
        # Serialize and encrypt the token JSON string
        token_json = json.dumps(value)
        self._token = cipher_suite.encrypt(token_json.encode('utf-8')).decode('utf-8')


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.String(50), primary_key=True)
    _username = db.Column("username", db.String, unique=True, nullable=False)
    _email = db.Column("email",db.String, unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    totp_secret = db.Column(db.String, nullable=True)
    
    @property
    def username(self):
        return cipher_suite.decrypt(self._username.encode('utf-8')).decode('utf-8')
    
    @username.setter
    def username(self, value):
        self._username = cipher_suite.encrypt(value.encode('utf-8')).decode('utf-8')
        
    @property
    def email(self):
        return cipher_suite.decrypt(self._email.encode('utf-8')).decode('utf-8')
    
    @email.setter
    def email(self, value):
        self._email = cipher_suite.encrypt(value.encode('utf-8')).decode('utf-8')
    
    
class OAuthUserData(db.Model):
    __tablename__ = 'oauth_user_data'

    id = db.Column(db.String(50), primary_key=True)
    _name = db.Column("name", db.String, nullable=False)
    _given_name = db.Column("given_name", db.String, nullable=False)
    _family_name = db.Column("family_name", db.String, nullable=False)
    _picture = db.Column("picture", db.String, nullable=False)

    # Encrypt and decrypt each field
    @property
    def name(self):
        return cipher_suite.decrypt(self._name.encode('utf-8')).decode('utf-8')

    @name.setter
    def name(self, value):
        self._name = cipher_suite.encrypt(value.encode('utf-8')).decode('utf-8')

    @property
    def given_name(self):
        return cipher_suite.decrypt(self._given_name.encode('utf-8')).decode('utf-8')

    @given_name.setter
    def given_name(self, value):
        self._given_name = cipher_suite.encrypt(value.encode('utf-8')).decode('utf-8')

    @property
    def family_name(self):
        return cipher_suite.decrypt(self._family_name.encode('utf-8')).decode('utf-8')

    @family_name.setter
    def family_name(self, value):
        self._family_name = cipher_suite.encrypt(value.encode('utf-8')).decode('utf-8')

    @property
    def picture(self):
        return cipher_suite.decrypt(self._picture.encode('utf-8')).decode('utf-8')

    @picture.setter
    def picture(self, value):
        self._picture = cipher_suite.encrypt(value.encode('utf-8')).decode('utf-8')
