import time
import webapp2
from google.appengine.ext import db

from helpers import *
from Model import *
from Handler import BlogHandler


class MainPageHandler(BlogHandler):
  def get(self):
      self.redirect_blog()


class SignupHandler(BlogHandler):
    def get(self):
        self.render_signup()

    def post(self):
        username = self.request.get('username')
        pw = self.request.get('pw')
        pw_conf = self.request.get('pw_conf')
        email = self.request.get('email')

        errors = dict()

        if not valid_username_format(username):
            errors["username_err"] = AuthError.invalid_username

        if not valid_pw_format(pw):
            errors["pw_err"] = AuthError.invalid_pw

        elif pw != pw_conf:
            errors["pw_conf_err"] = AuthError.invalid_pw_conf

        if not valid_email_format(email):
            errors["email_err"] = AuthError.invalid_email

        if bool(errors):
            self.render_signup(username, email, errors)
        else:
            self.done(self, username=username, pw=pw, email=email)

    def done(self, *a, **kw):
        username = self.request.get('username')
        pw = self.request.get('pw')
        email = self.request.get('email')

        u = User.by_name(username)
        if u:
            erros = { "username_err": AuthError.user_exist }
            self.render_signup(errors=erros)
        else:
            u = User.register(username, pw, email)
            u.put()
            self.login(u)


class LoginHandler(BlogHandler):
    def get(self):
        self.render_login()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
        else:
            self.render_login(AuthError.invalid_login)


class PostHandler(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        comments = Comment.all().filter('post_id =', int(post_id)).order('created')
        self.render_permalink(post=post, comments=comments)


class NewPostHandler(BlogHandler):
    def get(self):
        if self.user:
            self.render_new_post()
        else:
            self.redirect_login()

    def post(self):
        if not self.user:
            self.redirect_blog()

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, author_id=self.user.key().id())
            p.put()
            self.redirect_post(p.key().id())
        else:
            error = "subject and content, please!"
            self.render_new_post(subject, content, error)


class BlogFrontHandler(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render_front(posts=posts, user=self.user)


class EditPostHandler(BlogHandler):
    def get(self):
        if self.user:
            post_id = int(self.request.get('post_id'))
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if post.author_id != self.user.key().id():
                self.redirect_blog()

            self.render_edit_post(post)
        else:
            self.redirect_login()

    def post(self):
        if not self.user:
            self.redirect_blog()

        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)

        if post.author_id != self.user.key().id():
                self.redirect_blog()

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content

            post.put()
            self.redirect_post(post.key().id())
        else:
            error = "subject and content, please!"
            self.render_edit_post(post, error)


class DeletePostHandler(BlogHandler):
    def get(self):
        if self.user:
            post_id = int(self.request.get('post_id'))
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if post.author_id != self.user.key().id():
                self.redirect_blog()

            self.render_delete_post(post)
        else:
            self.redirect_login()

    def post(self):
        if not self.user:
            self.redirect_blog()

        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)

        if post.author_id != self.user.key().id():
            self.redirect_blog()

        post.delete()
        time.sleep(0.25)
        self.redirect_blog()


class NewCommentHandler(BlogHandler):
    def post(self):
        if not self.user:
            self.redirect_blog()

        post_id = int(self.request.get('post_id'))
        content = self.request.get('content')

        if post_id and content:
            c = Comment(parent=blog_key(), post_id=post_id, content=content,
                        author_id=self.user.key().id())
            c.put()
        self.redirect_post(post_id)


class EditCommentHandler(BlogHandler):
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)

            if not comment:
                self.error(404)
                return

            if comment.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render_edit_comment(comment)
        else:
            self.redirect_blog()

    def post(self):
        if not self.user:
            self.redirect_blog()

        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)

        if comment.author_id != self.user.key().id():
            self.redirect_blog()

        content = self.request.get('content')

        if content:
            comment.content = content
            comment.put()
            self.redirect_post(comment.post_id)
        else:
            error = "content, please!"
            self.render_edit_comment(comment, error)


class DeleteCommentHandler(BlogHandler):
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)

            if not comment:
                self.error(404)
                return

            if comment.author_id != self.user.key().id():
                self.redirect_blog()

            self.render_delete_comment(comment)
        else:
            self.redirect_login()

    def post(self):
        if not self.user:
            self.redirect_blog()

        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)

        if comment.author_id != self.user.key().id():
                self.redirect_blog()

        comment.delete()
        time.sleep(0.25)
        self.redirect_post(comment.post_id)


class LikeHandler(BlogHandler):
    def get(self):
        if self.user:
            if self.request.get('post_id'):
                item_id = post_id = int(self.request.get('post_id'))
                item = Post.by_id(item_id)
            elif self.request.get('comment_id'):
                item_id = int(self.request.get('comment_id'))
                item = Comment.by_id(item_id)
                post_id = item.post_id

            uid = self.user.key().id()
            if uid != item.author_id and uid not in item.liked:
                item.liked.append(uid)
                item.put()
                time.sleep(0.25)

            if self.request.get('permalink') == 'True':
                self.redirect_post(post_id)
            else:
                self.redirect_blog()

        else:
            self.redirect_login()


class DislikeHandler(BlogHandler):
    def get(self):
        if self.user:
            if self.request.get('post_id'):
                item_id = post_id = int(self.request.get('post_id'))
                item = Post.by_id(item_id)
            elif self.request.get('comment_id'):
                item_id = int(self.request.get('comment_id'))
                item = Comment.by_id(item_id)
                post_id = item.post_id

            uid = self.user.key().id()
            if uid in item.liked:
                item.liked.remove(uid)
                item.put()
                time.sleep(0.25)

            if self.request.get('permalink') == 'True':
                self.redirect_post(post_id)
            else:
                self.redirect_blog()
        else:
            self.redirect_login()


class LogoutHandler(BlogHandler):
    def get(self):
        self.logout()


app = webapp2.WSGIApplication([('/', MainPageHandler),
                               ('/blog/?', BlogFrontHandler),
                               ('/blog/([0-9]+)', PostHandler),
                               ('/blog/newpost', NewPostHandler),
                               ('/blog/newcomment', NewCommentHandler),
                               ('/blog/editpost', EditPostHandler),
                               ('/blog/deletepost', DeletePostHandler),
                               ('/blog/editcomment', EditCommentHandler),
                               ('/blog/deletecomment', DeleteCommentHandler),
                               ('/blog/like', LikeHandler),
                               ('/blog/dislike', DislikeHandler),
                               ('/signup', SignupHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler)],
                              debug=True)
