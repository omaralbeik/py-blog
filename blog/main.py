#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import string
import random
import hashlib
import hmac

import webapp2
from google.appengine.ext import db
import jinja2


#   _____ _       _           _
#  / ____| |     | |         | |
# | |  __| | ___ | |__   __ _| |
# | | |_ | |/ _ \| '_ \ / _` | |
# | |__| | | (_) | |_) | (_| | |
#  \_____|_|\___/|_.__/ \__,_|_|
############################################################

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

BLOG_NAME = "Omar's Blog"

SECRET = "nfyuBYUnuiGn*(^%@!jnd)aj8e!;kaHywsf-(2)124+_!"
USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
PW_RE = re.compile(r'^.{3,20}$')
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def make_salt():
    """Create salt"""
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_secure_val(val):
    """Return secure value of a string"""
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    """Check if secure value is valid"""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_pw_hash(username, pw, salt=None):
    """Return hashed password for a user"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pw_hash(username, pw, h):
    """Check if hash is valid for a user"""
    salt = h.split('|')[1]
    return h == make_pw_hash(username, pw, salt)


def is_username_valid(username):
    """Return true if username format is valid"""
    return username and USER_RE.match(username)


def is_pw_valid(pw):
    """Return true if password format is valid"""
    return pw and PW_RE.match(pw)


def is_email_valid(email):
    """Return true if email format is valid"""
    return email and EMAIL_RE.match(email)


def validate_username(username):
    """Return error string if username is not valid"""
    if not username:
        return "No username"
    elif not is_username_valid(username):
        return "Username is not valid"


def validate_pw(pw, pw_ver=None):
    """Return error string if password is not valid"""
    if pw and pw_ver and pw != pw_ver:
        return "Passwords don't match"
    elif not pw:
        return "No password"
    elif not is_pw_valid(pw):
        return "Password is not valid"


def validate_email(email):
    """Return error string if email is not valid"""
    if not is_email_valid(email):
        return "Email is not valid"


#  _    _                 _ _
# | |  | |               | | |
# | |__| | __ _ _ __   __| | | ___ _ __
# |  __  |/ _` | '_ \ / _` | |/ _ \ '__|
# | |  | | (_| | | | | (_| | |  __/ |
# |_|  |_|\__,_|_| |_|\__,_|_|\___|_|
############################################################
class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        """Write to response"""
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        """Render a string"""
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        """Render a template"""
        self.write(self.render_str(template, **kw))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and User.by_id(int(user_id))
        self.brand = BLOG_NAME

    def render_main(self, posts=None):
        """Render homepage"""
        if not posts:
            posts = Post.all().order('-created')
        self.render("index.html", user=self.user, brand=self.brand, posts=posts)

    def render_login(self, username=None,
                     username_error=None, pw_error=None, error=None):
        """Render login page"""
        self.render("login.html", username=username,
                    username_error=username_error, pw_error=pw_error,
                    error=error, user=self.user, brand=self.brand)

    def render_sign_up(self, username=None, pw=None, email=None,
                       username_error=None, pw_error=None, email_error=None,
                       error=None):
               """Render sign up page"""
               self.render("signup.html", username=username, pw=pw,
                           email=email, username_error=username_error,
                           pw_error=pw_error, email_error=email_error,
                           error=error, user=self.user, brand=self.brand)

    def render_new_post(self, title=None, body=None,
                        title_error=None, body_error=None):
        """Render new post page"""
        self.render("newpost.html", user=self.user, brand=self.brand,
                    title=title, body=body, title_error=title_error,
                    body_error=body_error)

    def render_my_posts(self):
        """Render my posts page"""
        self.render("myposts.html", user=self.user, brand=self.brand)

    def set_secure_cookie(self, name, value):
        """Set a hashed cookie with a name and a value"""
        cookie_val = make_secure_val(value)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Read a hashed cookie of a name"""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def sign_up(self, username, pw, email=None):
        if not User.by_username(username):
            pw_hash = make_pw_hash(username, pw)
            u = User(
                parent=users_key(),
                username=username,
                pw_hash=pw_hash,
                email=email
            )
            u.put()
            self.set_secure_cookie('user_id', str(u.key().id()))
            return u
        else:
            return None

    def login(self, username, pw):
        u = User.by_username(username)
        if u and valid_pw_hash(username, pw, u.pw_hash):
            self.set_secure_cookie('user_id', str(u.key().id()))
            return u
        else:
            return None

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

############################################################
############################################################


#  _____
# |  __ \
# | |__) |_ _  __ _  ___  ___
# |  ___/ _` |/ _` |/ _ \/ __|
# | |  | (_| | (_| |  __/\__ \
# |_|   \__,_|\__, |\___||___/
#              __/ |
#             |___/
############################################################


class MainPage(Handler):

    def get(self):
        self.render_main()


class LoginPage(Handler):

    def get(self):
        if self.user:
            self.redirect("/")
        else:
            self.render_login()

    def post(self):
        username = self.request.get('username')
        pw = self.request.get('pw')
        username_error = validate_username(username)
        pw_error = validate_pw(pw)

        if not (username_error or pw_error):
            u = self.login(username, pw)
            if u:
                self.redirect("/")
            else:
                self.render_login(username, username_error,
                                  pw_error, "Invalid username and/or password")
        else:
            self.render_login(username, username_error, pw_error)


class SignUpPage(Handler):

    def get(self):
        if self.user:
            self.redirect("/")
        else:
            self.render_sign_up()

    def post(self):
        username = self.request.get('username')
        pw = self.request.get('pw')
        pw_ver = self.request.get("pw_ver")
        email = self.request.get("email")
        username_error = validate_username(username)
        pw_error = validate_pw(pw, pw_ver)
        email_error = validate_email(email) if email else None

        if not (username_error or pw_error or email_error):
            u = self.sign_up(username, pw, email)
            if u:
                self.redirect("/")
            else:
                self.render_sign_up(username, pw, email, username_error,
                                    pw_error, email_error, "That user already exists!")
        else:
            self.render_sign_up(username, pw, email,
                                username_error, pw_error, email_error)


class LogoutPage(Handler):

    def get(self):
        self.logout()
        self.redirect("/")


class NewPostPage(Handler):

    def get(self):
        if self.user:
            self.render_new_post()
        else:
            self.redirect("/login")

    def post(self):
        title = self.request.get('title')
        body = self.request.get('body')
        title_error = None if title else "Please enter a title"
        body_error = None if body else "Please enter a body"

        if title_error or body_error:
            self.render_new_post(title=title, body=body,
                                 title_error=title_error, body_error=body_error)
        else:
            user_id = self.user.key().id()
            p = Post(parent=blog_key(), title=title,
                     body=body, author_id=user_id)
            p.put()
            self.redirect("/")


class MyPostsPage(Handler):

    def get(self):
        if self.user:
            self.render_my_posts()
        else:
            self.redirect("/login")


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/login', LoginPage),
    ('/signup', SignUpPage),
    ('/logout', LogoutPage),
    ('/newpost', NewPostPage),
    ('/myposts', MyPostsPage)
], debug=True)

############################################################
############################################################


#  _    _
# | |  | |
# | |  | |___  ___ _ __
# | |  | / __|/ _ \ '__|
# | |__| \__ \  __/ |
#  \____/|___/\___|_|
############################################################

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

############################################################
############################################################


#  _____          _
# |  __ \        | |
# | |__) |__  ___| |_
# |  ___/ _ \/ __| __|
# | |  | (_) \__ \ |_
# |_|   \___/|___/\__|
############################################################

def blog_key(name='default'):
    return db.Key.from_path('posts', name)


class Post(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    author_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)


    @classmethod
    def by_id(cls, uid):
        return Post.get_by_id(pid, parent=blog_key())

############################################################
############################################################


#   _____                                     _
#  / ____|                                   | |
# | |     ___  _ __ ___  _ __ ___   ___ _ __ | |_
# | |    / _ \| '_ ` _ \| '_ ` _ \ / _ \ '_ \| __|
# | |___| (_) | | | | | | | | | | |  __/ | | | |_
#  \_____\___/|_| |_| |_|_| |_| |_|\___|_| |_|\__|
############################################################

class Comment(db.Model):
    author_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, cid):
        return Comment.get_by_id(cid, parent=blog_key())
