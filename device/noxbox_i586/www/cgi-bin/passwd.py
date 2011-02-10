#!/usr/bin/env python
import cgi
import cgitb
import gen

cgitb.enable()


if gen.login_check() == False:
  gen.login_redirect()

else:
  gen.login_refresh()
  gen.print_header(': Web Password')
  print '\
  <form action="done.py" method="post">\
  <input type = hidden name="key" value = "passwd" />\
  \
  <p>Old password <input type="password" name="opass" />\
  <p>New password <input type="password" name="npass1" />\
  <p>Re-enter new password <input type="password" name="npass2" />\
  \
  <p><input type="submit" value="Submit" id="submit"/>\
  </form>\
  '
  gen.print_footer()
  print '\
  </html>\
  '
