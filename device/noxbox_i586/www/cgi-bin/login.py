#!/usr/bin/env python
import cgi
import cgitb
import gen

cgitb.enable()

print "Content-Type: text/html"
print
print '<html>\
<body>\
<form name="login" action="done.py" method="post">\
<input type = hidden name = "key" value = "login"/>\
<p>Enter password  <input type="password" name="pwd" />\
<input type="submit" value="Submit" id="submit"/>\
</form>\
<body onLoad="document.login.pwd.focus()">\
</html>\
'
