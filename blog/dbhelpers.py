import re
import string
import random
import logging

from google.appengine.ext import db
from handler import *


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_username(cls, username):
        return User.all().filter('username =', username).get()

    @classmethod
    def sign_up(cls, username, pw, email=None):
        if not cls.by_username(username):
            pw_hash = make_pw_hash(username, pw)
            u = User(parent=users_key(),
                     username=username,
                     pw_hash=pw_hash,
                     email=email)
            u.put()
            return u
        else:
            return None

    @classmethod
    def login(cls, username, pw):
        u = cls.by_username(username)
        if u and valid_pw_hash(username, pw, u.pw_hash):
            print(u.pw_hash)
            return u
        else:
            return None
