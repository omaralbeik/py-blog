from helpers import *
from google.appengine.ext import db

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """Get user by id"""
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        """Get user by name"""
        return User.all().filter('name =', name).get()

    @classmethod
    def register(cls, name, pw, email = None):
        """Register a new user"""
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        """Login with username and a password"""
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    author_id = db.IntegerProperty(required=True)
    liked = db.ListProperty(int, required=True)

    @classmethod
    def by_id(cls, pid):
        """Get post by id"""
        return Post.get_by_id(pid, parent=blog_key())

    def render(self, user, permalink):
        self._render_text = self.content.replace('\n', '<br>')
        self.liked_count = len(self.liked)
        return render_str("post.html", p=self, user=user,
                          author=User.by_id(int(self.author_id)),
                          permalink=permalink)


class Comment(db.Model):
    author_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    liked = db.ListProperty(int, required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, pid):
        """Get comment by id"""
        return Comment.get_by_id(pid, parent=blog_key())

    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        self.liked_count = len(self.liked)
        return render_str("comment.html", c=self, user=user,
                          author=User.by_id(int(self.author_id)))
