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

import webapp2
import cgi


def escape_html(s):
    return cgi.escape(s, quote=True)

months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']

months_abbrev = { m[:3].lower(): m for m in months }


def valid_month(month):
    month = month[:3].lower()
    return months_abbrev.get(month)


def valid_day(day):
    if day and day.isdigit():
        day = int(day)
        if 1 <= day <= 31:
            return day


def valid_year(year):
    if year and year.isdigit():
        year = int(year)
        if 1900 <= year <= 2020:
            return year


form = """<form method="post">
What is your birthday?
  <label>
    Month
    <input type="text" name="month" value="{month}">
  </label>
  <label>
    Day
    <input type="text" name="day" value="{day}">
  </label>
  <label>
    Year
    <input type="text" name="year" value="{year}">
  </label>
  <div style="color: red">{error}</div>

  <input type="submit">
</form>
"""


class MainPage(webapp2.RequestHandler):

    def write_form(self, error="", month="", day="", year=""):
        self.response.out.write(form.format(error=error,
                                            month=escape_html(month),
                                            day=escape_html(day),
                                            year=escape_html(year)))

    def get(self):
        self.write_form()

    def post(self):
        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')

        month = valid_month(user_month)
        day = valid_day(user_day)
        year = valid_year(user_year)

        if not (month and day and year):
            self.write_form("That doesn't look valid to me, friend.", user_month, user_day, user_year)
        else:
            self.redirect("/thanks")


class ThanksHandler(webapp2.RedirectHandler):
    def get(self):
        self.response.out.write("Thanks! That's a totally valid day!")


app = webapp2.WSGIApplication([ ('/', MainPage), ('/thans', ThanksHandler)],
                              debug=True)
