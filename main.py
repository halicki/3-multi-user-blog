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
import string
import re

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True
)


def render_str(template, **kwargs):
    template = jinja_env.get_template(template)
    return template.render(**kwargs)


class Handler(webapp2.RedirectHandler):
    def write(self, *args, **kwargs):
        self.response.out.write(*args, **kwargs)

    def render(self, template, **kwargs):
        self.write(render_str(template, **kwargs))


class MainPage(Handler):
    def get(self):
        items = [item for item in self.request.get_all("food") if len(item) > 0]
        self.render("shopping_list.html", items=items)


class FizzBuzz(Handler):
    def get(self):
        n = self.request.get('n')
        if n and n.isdigit():
            self.render("fizzbuzz.html", n=int(n))
        else:
            self.write("Provide nicer n.")


rot13 = string.maketrans(
    "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
    "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")


class Rot13(Handler):
    def get(self):
        self.render('rot13.html')

    def post(self):
        text = str(self.request.get('text'))
        self.render('rot13.html', text=text.translate(rot13))


class Welcome(Handler):
    def get(self):
        username = self.request.get('username')

        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('signup')


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
PASS_RE = re.compile(r"^.{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return email and EMAIL_RE.match(email)


class SignUp(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        if not valid_username(username):
            username_error = "That's not a valid username."

        if not valid_password(password):
            password_error = "That wasn't a valid password."

        if password != verify:
            verify_error = "Your passwords didn't match"

        if email and not valid_email(email):
            email_error = "That's not a valid email."

        if username_error or password_error or verify_error or email_error:
            self.render('signup.html',
                        username=username,
                        username_error=username_error,
                        password_error=password_error,
                        verify_error=verify_error,
                        email_error=email_error
                        )
        else:
            self.redirect('welcome?username={}'.format(username))


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/fizzbuzz', FizzBuzz),
                               ('/rot13', Rot13),
                               ('/signup', SignUp),
                               ('/welcome', Welcome)],
                              debug=True)
