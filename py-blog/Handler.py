import webapp2
from Model import User
from helpers import *

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """Save a cookie securely"""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Read a hashed cookie"""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """Save user id in a secure cookie"""
        self.set_secure_cookie('user_id', str(user.key().id()))
        self.redirect('/blog')

    def logout(self):
        """Delete user id cookie"""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/blog')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def render_front(self, posts, user):
        self.render('front.html', posts=posts, user=user)

    def render_login(self, error=None):
        self.render('login-form.html', error = error)

    def render_signup(self, username="", email="", errors=dict()):
        self.render('signup-form.html', username=username,
                                        email=email, errors = errors)

    def render_permalink(self, post, comments):
        self.render("permalink.html", post=post, comments=comments)

    def render_new_post(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content,
                                    error=error)

    def render_edit_post(self, post, error=""):
        self.render("editpost.html", post=post)

    def render_edit_comment(self, comment, error=""):
        self.render("editcomment.html", comment=comment, error=error)

    def render_delete_comment(self, comment):
        self.render("deletecomment.html", comment=comment)

    def render_delete_post(self, post):
        self.render("deletepost.html", post=post)

    def redirect_blog(self):
        self.redirect('/blog')

    def redirect_login(self):
        self.redirect('/login')

    def redirect_post(self, id):
        self.redirect('/blog/%s' % str(id))
