AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = README.md rfc1321/global.h rfc1321/md5.h

AM_CFLAGS = -DPROTOTYPES=1
AM_LDFLAGS = -module

pkglib_LTLIBRARIES = emd5.la

emd5_la_SOURCES = e_md5.c rfc1321/md5c.c

# Override some variables for the examples, this is NOT necessary
pkgdatadir = /usr/share/engine-corner
pkgexecdir = /usr/share/engine-corner/libexec
pkgincludedir = /usr/share/engine-corner/include
pkglibdir = /usr/share/engine-corner/lib
