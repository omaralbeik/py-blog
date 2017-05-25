import re
import os
import random
from string import letters
import hmac
import hashlib
import jinja2


SECRET = 'ijfkhs&(*%&*^@B)dsafaklhuysa&!##'
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


class AuthError:
    invalid_username = "Invalid username"
    invalid_pw = "Invalid password"
    invalid_pw_conf = "Passwords dont' match."
    invalid_email = "Invalid email"
    user_exist = "User already exists"
    invalid_login = "Invalid login"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def valid_username_format(username):
    """Return true if username is in valid format"""
    return username and USER_RE.match(username)

def valid_pw_format(pw):
    """Return true if password is in valid format"""
    return pw and PASS_RE.match(pw)

def valid_email_format(email):
    """Return true if email is in valid format"""
    return not email or EMAIL_RE.match(email)

def render_str(template, **params):
    """Render a template with parameters"""
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    """Return hased version of value"""
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    """Return nomal value from its hashed version"""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt(length = 5):
    """Make a salt of lenght"""
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    """Hash a password"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    """Check if password is valid for a username"""
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)
