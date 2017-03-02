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
import time
import hmac
import hashlib
import hashing


from google.appengine.ext import db
from google.appengine.api.datastore_types import datastore_errors

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True
)


def render_str(template, **kwargs):
    template = jinja_env.get_template(template)
    return template.render(**kwargs)


class Handler(webapp2.RequestHandler):
    def write(self, *args, **kwargs):
        self.response.out.write(*args, **kwargs)

    def render(self, template, **kwargs):
        self.write(render_str(template, **kwargs))


class ShoppingList(Handler):
    def get(self):
        items = [item for item in self.request.get_all("food") if len(item) > 0]
        self.render("shopping_list.html", items=items)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
PASS_RE = re.compile(r"^.{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return email and EMAIL_RE.match(email)


class Art(db.Model):
    title = db.StringProperty(required=True)
    art = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class MainPage(Handler):
    def render_front(self, title="", art="", error=""):
        arts = db.GqlQuery('SELECT * FROM Art '
                           'ORDER BY created DESC')
        self.render('front.html', title=title, art=art, error=error, arts=arts)

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get('title')
        art = self.request.get('art')

        if title and art:
            a = Art(title=title, art=art)
            a.put()
            time.sleep(0.1)
            self.redirect('/')
        else:
            self.render_front(title=title, art=art,
                              error='We need both title and art!')


class BlogPost(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Blog(Handler):
    def get(self):
        blog_posts = db.GqlQuery('SELECT * FROM BlogPost '
                                'ORDER BY created DESC '
                                'LIMIT 10')
        self.render('blog.html', blog_posts=blog_posts)


class Post(Handler):
    def get(self, blog_post_id):
        blog_post = BlogPost.get_by_id(int(blog_post_id))
        self.render('post.html', blog_post=blog_post)


class NewPost(Handler):
    def render_new_post(self, title="", content="", error=""):
        self.render('newpost.html', title=title, content=content, error=error)

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
            self.render_new_post(title, content, "Provide both, the title and content")


def hash_str(s):
    return hmac.new("secret", s, hashlib.sha256).hexdigest()


def make_secure_val(s):
    return "{}|{}".format(s, hash_str(s))


def check_secure_val(h):
    val = h.split('|', 1)[0]
    if make_secure_val(val) == h:
        return val


class VisitsCounter(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visits_cookie_val = self.request.cookies.get('visits', '0,0')
        if visits_cookie_val:
            print 'visits cookie val is set'
            cookie_val = check_secure_val(visits_cookie_val)
            if cookie_val:
                visits = int(cookie_val)

        visits += 1
        new_cookie_val = make_secure_val(str(visits))

        self.response.headers.add_header('Set-Cookie', 'visits={}'.format(new_cookie_val))

        if visits > 100:
            self.write("you are the best!")
        else:
            self.write("You've been here {} times.".format(visits))


class User(db.Model):
    hash = db.StringProperty(required=True)
    email = db.EmailProperty()
    registered_datetime = db.DateTimeProperty(auto_now_add=True)


class SignUp(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        errors = {}

        if not valid_username(username):
            errors['username_error']= "That's not a valid username."
        elif User.get_by_key_name(username):
            errors['username_error'] = "That name is already used."

        if not valid_password(password):
            errors['password_error'] = "That wasn't a valid password."

        if password != verify:
            errors['verify_error'] = "Your passwords didn't match"

        if email and not valid_email(email):
            errors['email_error'] = "That's not a valid email."

        if errors:
            errors.update(username=username, email=email)
            self.render('signup.html', **errors)
        else:
            User(key_name=username,
                 hash=hashing.make_pw_hash(username, password),
                 ).put()
            self.response.headers.add_header('Set-Cookie', 'user_id={}; Path=/'.format(
                hashing.make_secure_val(username)
            ))
            self.redirect('welcome')


class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.get_by_key_name(username)
        errors = {}

        if not user:
            errors['username_error'] = "No such user."

        if not hashing.valid_pw(username, password, user.hash):
            errors['password_error'] = "Invalid password."

        if errors:
            errors.update(username=username)
            self.render('login.html', **errors)
        else:
            self.response.headers.add_header('Set-Cookie', 'user_id={}; Path=/'.format(
                hashing.make_secure_val(username)
            ))
            self.redirect('welcome')


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('signup')


class Welcome(Handler):
    def get(self):
        user_id = self.request.cookies.get('user_id')
        if not user_id:
            self.redirect('signup')

        user_id = hashing.check_secure_val(user_id)
        if not user_id:
            self.redirect('signup')

        self.render('welcome.html', username=user_id)


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog/?', Blog),
    ('/blog/signup', SignUp),
    ('/blog/newpost', NewPost),
    ('/blog/(\d+)', Post),
    ('/blog/welcome', Welcome),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/shoppinglist', ShoppingList)],
    debug=True)
