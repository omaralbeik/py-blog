#!/usr/bin/env python

import os
import re
import string
import random
import hashlib
import hmac

import webapp2
import jinja2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

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

    def render_main(self):
        """Render homepage"""
        self.render("index.html")

    def render_login(self, username=None,
                     username_error=None, pw_error=None, error=None):
        """Render login page"""
        self.render("login.html", username=username,
                    username_error=username_error, pw_error=pw_error,
                    error=error)

    def render_sign_up(self, username=None, pw=None, email=None,
                       username_error=None, pw_error=None, email_error=None,
                       error=None):
               """Render sign up page"""
               self.render("signup.html", username=username, pw=pw,
                           email=email, username_error=username_error,
                           pw_error=pw_error, email_error=email_error,
                           error=error)


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
