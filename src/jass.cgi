#! /usr/bin/env python2.7
#
# A program intended to run as a CGI to run jass(1) on others behalf.
#
# Copyright (c) 2013, Twitter, Inc. All rights reserved.
#
# Originally written by Jan Schaumann <jschauma@twitter.com> in November
# 2013.

import cgi
import re
import subprocess
import sys

JASS = "/usr/bin/jass"
EXIT_FAILURE = 1
EXIT_SUCCESS = 0

###
### Functions
###

def error(msg):
    printHeader("text/html")
    html="""
<HTML>
	<HEAD>
		<TITLE>JassBird - Error</TITLE>
	</HEAD>
	<BODY>
		<H1>Error</H1>
		%s
		<HR>
		<P>Back to <A HREF="your-jass-url-here">Jass</A></P>
	</BODY>
</HTML>
    """
    print html % msg
    sys.exit(EXIT_FAILURE)


def printHeader(contentType):
    print "Content-Type: %s\n" % contentType


def validateInput(form):
    valid = re.compile(r"^[a-z0-9._, -]+$", re.I)
    users = form["users"].value
    groups = form["groups"].value
    if (users and not valid.match(users)) or \
        (groups and not valid.match(groups)):
        error("Invalid data in user/group field.")

###
### "Main"
###

def main():
    form = cgi.FieldStorage()
    users = []
    groups = []
    cmd = [ JASS ]

    try:
        if not (form["users"].value or form["groups"].value):
            error("You need to provide at least one user or one group.")

        if form["text"].value and form["infile"].value:
            error("You cannot specify input data <em>and</em> a file simultaneously.")

        validateInput(form)

        if form["users"].value:
            users = map(str.strip, form["users"].value.split(","))
        if form["groups"].value:
            groups = map(str.strip, form["groups"].value.split(","))

        data = form["text"].value
        if not data:
            data = form["infile"].value

        for u in users:
	    cmd.extend(["-u", u])

        for g in groups:
	    cmd.extend(["-g", g])

        jass = subprocess.Popen(cmd, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = jass.communicate(data)

        if jass.returncode != 0:
            errmsg = "jass(1) failed!"
            if err:
                errmsg += " Stderr below:<br>\n<pre><tt>%s</tt></pre>" % err
            error(errmsg)

        printHeader("text/plain")
        print out

    except KeyError, e:
        error("Invalid form submission.")


main()
