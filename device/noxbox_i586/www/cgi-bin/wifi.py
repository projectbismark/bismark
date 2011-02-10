#!/usr/bin/env python
import cgi
import cgitb
import gen

cgitb.enable()


if gen.login_check() == False:
  gen.login_redirect()

else:
  gen.login_refresh()
  gen.print_header(': Wireless')

  curressid = gen.currval('WIFI_SSID')
  currpass = gen.currval('WIFI_PASS')
  currenc = gen.currval('WIFI_SEC')
  noenc,wepenc,wpaenc,wpa2enc = gen.encval(currenc)

  print '\
  <form action="done.py" method="post">\
  <input type = hidden name="key" value = "wifi" />\
  \
  What type of encryption?\
  <input type=radio name="newenc" value="None" %s >None\
  <input type=radio name="newenc" value="WEP" %s >WEP\
  <input type=radio name="newenc" value="WPA" %s >WPA\
  <input type=radio name="newenc" value="WPA2" %s >WPA2\
   \
  <p>New Name for Wireless Network (Current Name: %s) <input type="text" name="essid" />\
   \
  <p>New Passphrase (Current passphrase: %s) <input type="text" name="pass" />\
  \
  <p><input type="submit" value="Submit" id="submit"/>\
  </form>\
  '%(noenc,wepenc,wpaenc,wpa2enc,curressid,currpass)

  gen.print_footer()
  print '\
  </html>\
  '
