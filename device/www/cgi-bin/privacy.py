#!/usr/bin/env python
import cgi
import cgitb
import gen

cgitb.enable()


def priv_options():
  gen.login_refresh()
  gen.print_header(': Private Browsing')
  priv = gen.currval('PRIVACY_MODE')
  priv = priv.replace('"','')
  priv = priv.replace('\n','')
  if priv.upper() != 'ON':
    print '\
    <p>No privacy options available\
    '
    return
  print '\
  <form action="done.py" method="post">\
  <input type = hidden name="key" value = "privacy" />\
  \
  How long do you want private browsing enabled?\
  <input type=radio name="dur" value="5">5 minutes\
  <input type=radio name="dur" value="15">15 minutes\
  <input type=radio name="dur" value="30">30 minutes\
   \
  <p><input type="submit" value="Submit" id="submit"/>\
  </form>\
  '
  gen.print_footer()
  print '\
  </html>\
  '

if gen.login_check() == False:
  gen.login_redirect()
else:
  priv_options()
