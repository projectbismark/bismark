#!/bin/sh

aclocal
autoconf
libtoolize --force --copy
automake --add-missing --force-missing --copy
autoheader

