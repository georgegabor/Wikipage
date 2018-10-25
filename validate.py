import re

Uname = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
Upass = re.compile(r"^.{3,20}$")
Uemail = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def validUsername(username):
	if Uname.match(username) == None:
		return False
	else:
		return True		

def validPassword(password):	
	if Upass.match(password) == None:
		return False
	else:
		return True

def validVerify(verify,password):	
	if (Upass.match(verify) == None) or (password != verify) :
		return False
	else:
		return True

def validEmail(email):	
	if email == "":
		return True
	elif Uemail.match(email) == None:
		return False
	else:
		return True


if __name__ == "__main__":
	u = raw_input("Enter email: ")
	print(validEmail(u))