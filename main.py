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
        self.render("rot13.html")

    def post(self):
        text = str(self.request.get('text'))
        self.render("rot13.html", text=text.translate(rot13))


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/fizzbuzz', FizzBuzz),
                               ('/rot13', Rot13)], debug=True)
