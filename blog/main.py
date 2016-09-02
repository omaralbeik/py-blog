#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
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
#
import os
import re

import webapp2
import jinja2
import dbhelpers
from handler import *
from dbhelpers import User


class MainPage(Handler):

    def get(self):
        self.render_main()

class LoginPage(Handler):

    def get(self):
        self.render_login()

    def post(self):
        username = self.request.get('username')
        pw = self.request.get('pw')
        username_error = validate_username(username)
        pw_error = validate_pw(pw)

        if not (username_error or pw_error):
            u = User.login(username, pw)
            if u:
                self.write("Success")
            else:
                self.render_login(username, username_error, pw_error, "Invalid username and/or password")
        else:
            self.render_login(username, username_error, pw_error)


class SignUpPage(Handler):

    def get(self):
        self.render_sign_up()

    def post(self):
        username = self.request.get('username')
        pw = self.request.get('pw')
        pw_ver = self.request.get("pw_ver")
        email = self.request.get("email")
        username_error = validate_username(username)
        pw_error = validate_pw(pw, pw_ver)
        email_error = ""
        if email:
            email_error = validate_email(email)

        if not (username_error or pw_error or email_error):
            if User.by_username(username):
                self.render_sign_up(username, pw, email, username_error, pw_error, email_error, "That user already exists!")
            else:
                u = User.sign_up(username, pw, email)
                u.put()
                self.write("Success")
        else:
            self.render_sign_up(username, pw, email, username_error, pw_error, email_error)


app = webapp2.WSGIApplication([
    ('/', MainPage), ('/login', LoginPage), ('/signup', SignUpPage)
], debug=True)
