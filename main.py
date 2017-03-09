#!/usr/bin/env python2
# -*- coding=UTF-8

import jinja2
import webapp2
from webapp2 import Route
from webapp2_extras import routes
import os
import re
import hashlib
import hmac
import random
import string
import time
from google.appengine.ext import db

import pdb
import pprint


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True
)


class Handler(webapp2.RequestHandler):
    user = None

    @staticmethod
    def render_str(template, **kwargs):
        template = jinja_env.get_template(template)
        return template.render(**kwargs)

    def write(self, *args, **kwargs):
        self.response.out.write(*args, **kwargs)

    def render(self, template, **kwargs):
        self.write(self.render_str(template, user=self.user, **kwargs))

    def read_cookie(self, name):
        cookie = self.request.cookies.get(name)
        return cookie and check_secure_val(cookie)

    def clear_cookie(self, name):
        self.response.headers.add_header('Set-Cookie', '{}=;'.format(name))

    def set_cookie(self, name, value, path=None):
        value = make_secure_val(value)
        path = path or '/'
        self.response.headers.add_header(
            'Set-Cookie', '{0}={1}; Path={2}'.format(name, value, path))

    def initialize(self, *a, **kw):
        super(Handler, self).initialize(*a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))

    def login_user(self, user_key):
        self.set_cookie('user_id', str(user_key.id()))

    def logout_user(self):
        self.clear_cookie('user_id')

    @staticmethod
    def require_login(func):
        def method_wrapper(self, *args, **kwargs):
            if not self.user:
                self.uri_for('/signup')
            else:
                func(self, *args, **kwargs)
        return method_wrapper


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.EmailProperty()
    registered_datetime = db.DateTimeProperty(auto_now_add=True)


def hash_str(s):
    return hmac.new("secret", s, hashlib.sha256).hexdigest()


def make_secure_val(s):
    return "{}|{}".format(s, hash_str(s))


def check_secure_val(h):
    val = h.split('|', 1)[0]
    if make_secure_val(val) == h:
        return val


def make_salt():
    return ''.join(random.choice(string.ascii_letters) for _ in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    name_pw_hash = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (name_pw_hash, salt)


def valid_pw(name, pw, h):
    db_hash, salt = h.split('|')
    computed_hash = make_pw_hash(name, pw, salt)
    return h == computed_hash


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
PASS_RE = re.compile(r"^.{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return email and EMAIL_RE.match(email)


class SignUpHandler(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        params = {'username': username, 'email': email}
        error = False

        if not valid_username(username):
            params['username_error']= "That's not a valid username."
            error = True
        elif User.all().filter('username =', username).get():
            params['username_error'] = "That name is already used."
            error = True

        if not valid_password(password):
            params['password_error'] = "That wasn't a valid password."
            error = True
        if password != verify:
            params['verify_error'] = "Your passwords didn't match"
            error = True

        if email and not valid_email(email):
            params['email_error'] = "That's not a valid email."
            error = True

        if error:
            self.render('signup.html', **params)
        else:
            user_key = User(username=username, email=email or None,
                            pw_hash=make_pw_hash(username, password)).put()
            self.login_user(user_key)
            self.redirect('welcome')


class LoginHandler(Handler):
    def render_login(self, **kwargs):
        self.render('login.html', **kwargs)

    def get(self):
        self.render_login()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        params = {username: username}
        user = User.all().filter('username =', username).get()
        error = False

        if not user:
            params['username_error'] = "No such user."
            error = True
        elif not password:
            params['password_error'] = "Please provide password."
            error = True
        elif not valid_pw(username, password, user.pw_hash):
            params['password_error'] = "Invalid password."
            error = True

        if error:
            self.render_login(**params)
        else:
            self.login_user(user.key())
            self.redirect('welcome')


class LogoutHandler(Handler):
    def get(self):
        self.logout_user()
        self.redirect('signup')


class WelcomeHandler(Handler):
    @Handler.require_login
    def get(self):
        self.render('welcome.html', username=self.user.username)


class BlogPost(db.Model):
    author = db.ReferenceProperty(User)
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def from_string_id(cls, blog_post_id):
        return BlogPost.get_by_id(int(blog_post_id))

    def get_likes(self):
        return Like.all().filter('post =', self)

    def render(self, **kwargs):
        likes = Like.all().filter('post =', self).fetch(None)
        template = jinja_env.get_template("blogpost.html")
        return template.render(bp=self, likes=self.get_likes().fetch(20),
                               **kwargs)

    def uri_for(self, action='post-view'):
        return webapp2.uri_for(action, post=str(self.key().id()))


class MainHandler(Handler):
    def get(self):
        blog_posts = db.GqlQuery('SELECT * FROM BlogPost '
                                 'ORDER BY created DESC '
                                 'LIMIT 10')
        self.render('main.html', blog_posts=blog_posts)


class NewPostHandler(Handler):
    def render_new_post(self, title="", content="", error=""):
        self.render('edit-post.html', title=title, content=content, error=error)

    @Handler.require_login
    def get(self):
        self.render_new_post()

    @Handler.require_login
    def post(self):
        title = self.request.get('subject')
        content = self.request.get('content')

        if title and content:
            blog_post = BlogPost(title=title, content=content,
                                 author=self.user.key())
            blog_post.put()
            self.redirect(blog_post.uri_for())
        else:
            self.render_new_post(title, content,
                                 "Provide both, the title and content")


class ValidBlogPostIDHandler(Handler):
    blog_post = None

    def initialize(self, *a, **kw):
        super(ValidBlogPostIDHandler, self).initialize(*a, **kw)
        post_id = self.request.route_kwargs.pop('post')
        self.blog_post = BlogPost.from_string_id(post_id)
        if not self.blog_post:
            self.abort(404)

    @staticmethod
    def require_blog_post_author(func):
        def method_wrapper(self, *args, **kwargs):
            if self.blog_post.author.key() != self.user.key():
                # TODO: PRODUCE A WARNING MESSAGE
                self.uri_for('/')
            else:
                func(self, *args, **kwargs)
        return method_wrapper


class ViewPostHandler(ValidBlogPostIDHandler):
    def get(self):
        coms = Comment.gql('WHERE blog_post = :1 '
                           'ORDER BY created DESC', self.blog_post).fetch(None)
        self.render('post.html', blog_post=self.blog_post, comments=coms)


class Like(db.Model):
    post = db.ReferenceProperty(BlogPost)
    author = db.ReferenceProperty(User)
    clicked_on = db.DateTimeProperty(auto_now_add=True)


class LikeHandler(ValidBlogPostIDHandler):
    def toggle(self):
        like = self.blog_post.get_likes().filter('author =', self.user).get()
        if like:
            like.delete()
        else:
            Like(post=self.blog_post, author=self.user).put()

    @Handler.require_login
    def post(self):
        self.toggle()
        time.sleep(0.1)
        self.redirect(webapp2.uri_for('main'))


class EditPostHandler(ValidBlogPostIDHandler):
    def _render_edited_post(self, title="", content="", error=""):
        self.render('edit-post.html', title=title, content=content, error=error)

    @Handler.require_login
    @ValidBlogPostIDHandler.require_blog_post_author
    def get(self):
        self._render_edited_post(title=self.blog_post.title,
                                 content=self.blog_post.content)

    @Handler.require_login
    @ValidBlogPostIDHandler.require_blog_post_author
    def post(self):
        title = self.request.get('subject')
        content = self.request.get('content')

        if title and content:
            self.blog_post.title = title
            self.blog_post.content = content
            self.blog_post.put()
            self.redirect(self.blog_post.uri_for())
        else:
            self._render_edited_post(title, content,
                                    "Provide both, the title and content")


class DeletePostHandler(ValidBlogPostIDHandler):
    @Handler.require_login
    @ValidBlogPostIDHandler.require_blog_post_author
    def post(self):
        self.blog_post.delete()
        time.sleep(0.1)
        self.redirect('/')


class Comment(db.Model):
    blog_post = db.ReferenceProperty(BlogPost)
    author = db.ReferenceProperty(User)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(required=True, auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        return jinja_env.get_template('comment.html').render(comment=self)


class CommentHandler(ValidBlogPostIDHandler):
    def _render(self, *args, **kwargs):
        self.render('edit-comment.html', *args, **kwargs)

    @Handler.require_login
    def get(self):
        self._render()

    @Handler.require_login
    def post(self):
        content = self.request.get('content')

        if content:
            comment = Comment(blog_post=self.blog_post, author=self.user,
                              content=content)
            comment.put()
            time.sleep(0.1)
            self.redirect(self.blog_post.uri_for())
        else:
            self._render(error="Please provide content.")


app = webapp2.WSGIApplication([
    Route(r'/', MainHandler, 'main'),
    Route(r'/signup', SignUpHandler, 'signup'),
    Route(r'/login', LoginHandler, 'login'),
    Route(r'/logout', LogoutHandler, 'logout'),
    Route(r'/welcome', WelcomeHandler, 'welcome'),
    Route(r'/new-post', NewPostHandler, 'new-post'),
    routes.PathPrefixRoute(r'/posts/<post:\d+>', [
        Route('/', ViewPostHandler, 'post-view'),
        Route('/likes', LikeHandler, 'post-likes'),
        Route('/edit', EditPostHandler, 'post-edit'),
        Route('/delete', DeletePostHandler, 'post-delete'),
        Route('/comments', CommentHandler, 'post-comments')
    ])
], debug=True)
