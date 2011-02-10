#!/usr/bin/env python
import CGIHTTPServer
import BaseHTTPServer

HOST_NAME = '10.100.0.1'
PORT_NUMBER = 80
class Handler(CGIHTTPServer.CGIHTTPRequestHandler):cgi_directories = [""]


if __name__ == '__main__':
  server_class = BaseHTTPServer.HTTPServer
  httpd = server_class((HOST_NAME, PORT_NUMBER), Handler)
  httpd.serve_forever()

