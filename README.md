excesspy
========

excesspy is a python port of Alla Bezroutchko's excess2, a perl tool to test XSS on mail clients.
The original perl script can be found here: http://www.gremwell.com/sites/default/files/excess2.pl_.txt
More information about the per script: http://www.gremwell.com/excess2_webmail_xss_tester

It currently is an excact port of Alla's original tool, with the addition of MIME support. 

Goal is to add other attack vectors to the tool at later stages, when the need for them arises.

Usage:
=======
excess.py -s smtp_server -f sender_address -t recipient_address

Requirements
============
Requires the following libraries:
	*	smtplib
	*	sys
	*	optparse
	*	urllib2
	*	xml.dom.minidom
	*	HTMLParser

Tested on python 2.7.3

