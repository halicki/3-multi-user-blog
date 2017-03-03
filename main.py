# Copyright 2016 Google Inc.
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

import jinja2
import webapp2
import os
import re
import hashlib
import hmac
import random
import string
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True
)


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
def valid_username(username):
    return username and USER_RE.match(username)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_password(password):
    return password and PASS_RE.match(password)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_email(email):
    return email and EMAIL_RE.match(email)


class Handler(webapp2.RequestHandler):

    @staticmethod
    def render_str(template, **kwargs):
        template = jinja_env.get_template(template)
        return template.render(**kwargs)

    def write(self, *args, **kwargs):
        self.response.out.write(*args, **kwargs)

    def render(self, template, **kwargs):
        self.write(self.render_str(template, **kwargs))

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
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.logged_user = uid and User.get_by_id(int(uid))

    def login_user(self, user_key):
        self.set_cookie('user_id', str(user_key.id()))

    def logout_user(self):
        self.clear_cookie('user_id')


class BlogPost(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class PostHandler(Handler):
    def get(self, blog_post_id):
        blog_post = BlogPost.get_by_id(int(blog_post_id))
        self.render('post.html', blog_post=blog_post)


class NewPostHandler(Handler):
    def render_new_post(self, title="", content="", error=""):
        self.render('newpost.html', title=title, content=content,
                    error=error)

    def get(self):
        self.render_new_post()

    def post(self):
        title = self.request.get('subject')
        content = self.request.get('content')

        if title and content:
            blog_post = BlogPost(title=title, content=content)
            blog_post.put()
            self.redirect(str(blog_post.key().id()))
        else:
            self.render_new_post(title, content,
                                 "Provide both, the title and content")


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.EmailProperty()
    registered_datetime = db.DateTimeProperty(auto_now_add=True)


class MainHandler(Handler):
    def get(self):
        blog_posts = db.GqlQuery('SELECT * FROM BlogPost '
                                'ORDER BY created DESC '
                                'LIMIT 10')
        self.render('blog.html', blog_posts=blog_posts)


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
    def get(self):
        if not self.logged_user:
            self.redirect('signup')
        else:
            self.render('welcome.html', username=self.logged_user.username)


app = webapp2.WSGIApplication([
    ('/?', MainHandler),
    ('/signup', SignUpHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/welcome', WelcomeHandler),
    ('/newpost', NewPostHandler),
    ('/(\d+)', PostHandler)],
    debug=True)
