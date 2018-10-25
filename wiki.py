import re
import validate
import hashlib
import hmac
import os 
import time
import webapp2 
import jinja2
import json
import logging
import datetime
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)
secret = u"687897689^&2"

#~~~~~~~~~~~~~~~~~~~~~~~~ The Database Models ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

class Content(db.Model):
	content_url = db.StringProperty(required=True)
	contents = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)

class User(db.Model):
	username = db.StringProperty( required = True )
	password = db.StringProperty( required = True )
	email = db.StringProperty()

	#if user valid set cookie
	@staticmethod
	def register( username, password, email):
		hashed_password = Secret.hash_password(password)
		new_user = User( username = username, password = hashed_password, email = email )
		new_user.put()
		userid = str(new_user.key().id())
		cookie = Secret.hash_cookie(userid)
		return cookie

	@staticmethod
	def get_user_by_cookie(cookie):
		userid = (cookie.split('|')[0]).split('=')[1]
		user = User.get_by_id(int(userid))
		return user.username

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Hashing  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

class Secret():
	# make_salt is not used, but i leave it here :-)
	def make_salt():
		return ''.join(random.choice(letters) for x in xrange(5))

	@staticmethod	
	def hash_password(password):
		return hashlib.sha256(password).hexdigest()

	@staticmethod
	def hash_cookie(val):
		return '%s|%s' % (val, hmac.new(str(secret), str(val)).hexdigest())	

################################################ Handlers ##########################################
#
# Order : Default Handler -> Signup -> Login -> Logout -> Edit -> ViewPage -> HistoryPage
#
####################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~ Default Handler for Jinja  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		cookie = self.request.headers.get("Cookie")
		url = params["path"]
		params["URL"] = url
		if cookie:
			params["User"] = User.get_user_by_cookie(cookie)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def render_page(self, url, html):
		path = re.split(r'^(/_history|/_edit)', url)[-1]
		u = Content.all().filter('content_url', path).get()
		if not u:
			self.redirect(r'/_edit' + path)	
		else:
			content = db.GqlQuery("select * from Content where content_url=:1", path)
			self.render(html, contents=content, path=path)		

#~~~~~~~~~~~~~~~~~~~~~~~~ The Signup Handler ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

class Signup(Handler):
	def render_signup(self, **params):
		params["path"] = self.request.url
		self.render("signupform.html", **params)

	def get(self, **params):
		self.render_signup(**params)

	def post(self):
		params = dict()
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		validUsername = validate.validUsername(username)
		validPassword = validate.validPassword(password)
		validVerify = validate.validVerify(verify,password)
		validEmail = validate.validEmail(email)

		u = User.all().filter('username', username ).get()
		if not u: 
			if (validUsername and validPassword and validVerify and validEmail):			
				new_user = User.register(username, password, email)
				self.response.set_cookie(key='userid', value=new_user)
				self.redirect("/")
				
			else:
				if not validUsername:
					params["usernameerror"] = "That's not a valid username."
				if not validPassword:
					params["passworderror"] = "That's not a valid password."
				if validPassword and not validVerify:
					params["verifyerror"] = "Your passwords didn't match."
				if not validEmail:
					params["emailerror"] = "That's not a valid email."
				self.render_signup(**params)
		else:
			self.render_signup(usernameerror="User already exists !")				
		
#~~~~~~~~~~~~~~~~~~~~~~~~  The Login Handler ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

class Login(Handler):
	def get(self, **params):
		params["path"] = self.request.url
		self.render("login.html", **params)

	def post(self, **params):
		username = self.request.get('username')
		password = Secret.hash_password(self.request.get('password'))
		params["path"] = self.request.url
		user = User.all().filter('username', username ).get()
		if not user:	
			params["usernameerror"] = "User doesn't exist !!!"
			self.render("login.html", **params)
		else:
			if user.password == password:
				userid = str(user.key().id())
				cookie = Secret.hash_cookie(userid)
				self.response.set_cookie(key='userid', value=cookie, path='/')
				self.redirect("/")				
			else:
				params["passworderror"] = "Passwort stimmt nicht !!!"	
				self.render("login.html", **params)

#~~~~~~~~~~~~~~~~~~~~~~~~  The Logout Handler ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

class Logout(Handler):
	def get(self):
		self.response.set_cookie(key='userid', value=None, path='/')
		self.redirect(r"/signup")

#~~~~~~~~~~~~~~~~~~~~~~~~ Edit Handlers ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

class EditPage(Handler):
	def render_editpage(self, url):
		path = re.split(r'^(/_history|/_edit)', url)[-1]
		content = Content.all().filter('content_url', path)
		self.render("edit.html", contents=content, path=path)

	def get(self, url):
		cookie = self.request.headers.get("Cookie")
		if cookie:
			self.render_editpage(url)
		else:
			self.redirect(r"/login")

	def post(self, url):
		url = self.request.url
		path = url.split('/_edit')[-1]
		contents = self.request.get('content')
		new_content = Content(content_url=path, contents=contents)
		new_content.put()
		time.sleep(1)
		self.redirect(path)

#~~~~~~~~~~~~~~~~~~~~~~~~ Viewpage Handler ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

class ViewPage(Handler):
	def get(self, url):
		self.render_page(url=url, html="view.html")
		
#~~~~~~~~~~~~~~~~~~~~~~~~ HistoryPage Handler ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

class HistoryPage(Handler):
	def get(self, url):
		self.render_page(url=url, html="history.html" )
		
#~~~~~~~~~~~~~~~~~~~~~~~~ The Handler Handler :-) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PAGE_RE = '<:/.*>'
app = webapp2.WSGIApplication([
								webapp2.Route(r'/signup', handler=Signup),
								webapp2.Route(r'/login', handler=Login),
								webapp2.Route(r'/logout', handler=Logout),
								webapp2.Route(r'/_edit' + PAGE_RE, handler=EditPage),
								webapp2.Route(r'/_history' + PAGE_RE, handler=HistoryPage),
								webapp2.Route(r'/_view' + PAGE_RE, handler=ViewPage),
								webapp2.Route(PAGE_RE, handler=ViewPage),
    							], debug = True)		


