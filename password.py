
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, request
from flask_bcrypt           import Bcrypt

appBcrypt = Flask(__name__)
bcryptObj = Bcrypt(appBcrypt)

#print (generate_password_hash("Marcador@zul1"))

print("Hola")

password = "Marcador@zul1"

hashPassword = bcryptObj.generate_password_hash(password).decode('utf8')

pw_hash = bcryptObj.generate_password_hash("hunter2").decode('utf-8')

print(hashPassword)

print(pw_hash)

if bcryptObj.check_password_hash(pw_hash, 'hunter2'):
    print ("Hola perro")
else:
    print("No soy perro")
