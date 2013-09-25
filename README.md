excesspy
========

excesspy is a python port of Alla Bezroutchko's excess2, a perl tool to test XSS on mail clients.
The original perl script can be found here: http://www.gremwell.com/sites/default/files/excess2.pl_.txt
More information about the per script: http://www.gremwell.com/excess2_webmail_xss_tester

The xssAttacks.xml file you find in this repo is a download of http://ha.ckers.org/xssAttacks.xml, created and maintained by RSnake.


It currently is an excact port of Alla's original tool, with the addition of MIME support. 

Goal is to add other attack vectors to the tool at later stages, when the need for them arises.

Usage:
=======
Command Line:
-------------
excess.py -s smtp_server -f from -t to -a [XSS or DIR] --param [XSS: Fieldname, DIR: path]

XSS:
----
-a "XSS": (default) will retireve XML containing XSS exploits from http://ha.ckers.org/xssAttacks.xml
--param: decides which field will be injected, can be set to ALL (default), FROM, TO, SUBJECT,BODY or HEADER.

DIR:
-----
-a "DIR": will read all files in a directory and email them. The files must contain a full message including headers. Values $from$ $to$ and $subject$ will be replaced with their correspondingv alue when specified.
--param: the directory which will be read, when -a is set to "DIR" this parameter is mandatory


Options:
  -h, --help            show this help message and exit
  -s SMTP_SERVER        
  -p SMTP_PORT          
  -f SMTP_FROM          
  -t SMTP_TO            
  -a ATTACK_TYPE        
  --param=ATTACK_SUB_TYPE


Requirements
============
Requires the following libraries:
	*	smtplib
	*	sys
	*	optparse
	*	urllib2
	*	xml.dom.minidom
	*	HTMLParser
	* 	os

Tested on python 2.7.3, only linux supported

