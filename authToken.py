import asyncio
import tornado.ioloop
import tornado.web
from tornado.web import Finish
from datetime import datetime
import json
import uuid
import hmac
import hashlib
import base64

# Port
HTTP_PORT = 8888

# App key + secret
APPLICATION_KEY = 'INSERT_YOUR_APP_KEY_HERE'
APPLICATION_SECRET = 'INSERT_YOUR_APP_SECRET_HERE'

userBase = dict()

# Generate authentication token.

def generateAuthenticationToken(user):
    userToken = {
        'identity': {'type': 'username', 'endpoint': user['username']},
        'expiresIn': 3600,
        'applicationKey': APPLICATION_KEY,
        'created': datetime.utcnow().isoformat()
    }
    
    userTokenJson = json.dumps(userToken, separators=(" ", ""))
    userTokenBase64 = base64.b64encode(userTokenJson.encode())
    
    digest = hmac.new(APPLICATION_SECRET.encode(), userTokenBase64, hashlib.sha256).digest()
    signature = base64.b64encode(digest)
    
    signedUserToken = userTokenBase64.decode() + ':' + signature.decode()
    return {'userToken': signedUserToken}
    
    
    
# REST endpoints
class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Hello, world")

# REST endpoints
class PingHandler(tornado.web.RequestHandler):

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Content-Type", "application/json; charset=UTF-8")

    def get(self):
        self.write('pong')

class RestResource(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Content-Type", "application/json; charset=UTF-8")
    def write_error(self, status_code, **kwargs):
        data = {key: value for key, value in kwargs.items() if key != 'exc_info'}
        self.write(json.dumps(data))
        self.set_status(status_code)
        raise Finish()
    
class RegisterHandler(RestResource):
    def post(self):
        user = json.loads(self.request.body)
        if 'username' not in user:
            self.write_error(400,errorCode=40001, message='username not found')
        if 'password' not in user:
            self.write_error(400,errorCode=40002, message='password not found')
        if user['username'] in userBase:
            self.write_error(400,errorCode=40003, message='username already exists')
        salt = uuid.uuid4().hex
        userBase[user['username']] = salt + hashlib.sha256(salt.encode() + user['password'].encode()).hexdigest()
        
        print('User ' + user['username'] + ' created')
        for name in userBase:
            print(name + ': ' + userBase[name] )
            
        self.write(json.dumps(generateAuthenticationToken(user)))

class LoginHandler(RestResource):
    def post(self):
        user = json.loads(self.request.body)
        if 'username' not in user:
            self.write_error(400,errorCode=40001, message='username not found')
        if 'password' not in user:
            self.write_error(400,errorCode=40002, message='password not found')
        if user['username'] not in userBase:
            self.write_error(400,errorCode=40004, message='username not found')
        
        #
        username = user['username']
        storedPass = userBase.get(user['username'])
        salt = storedPass[:32]
        usersHashedPassword = hashlib.sha256(
            salt.encode() + user['password'].encode()).hexdigest()
        
        if usersHashedPassword != storedPass[32:]:
            self.write_error(400,errorCode=40005, message='incorrect password')
        else:
            print('User ' + user['username'] + ' logged in')
            self.write(json.dumps(generateAuthenticationToken(user)))

            

backend = tornado.web.Application([
    (r"/", MainHandler),
    (r"/ping", PingHandler),
    (r"/register", RegisterHandler),
    (r"/login", LoginHandler)
  
])

if __name__ == "__main__":
    print(
        "Starting demo backend on port: \033[1m" + str(HTTP_PORT) + '\033[0m')
    print("Application key: \033[1m" + APPLICATION_KEY + '\033[0m')
    print("Post JSON object to \033[1m/register\033[0m to create user")
    print(
        "Post JSON object to \033[1m/login\033[0m to retrieve authentication token")
    print(
        "Example JSON: {username: 'username here', password: 'password here'}")
    print("--- LOG ---")

    backend.listen(HTTP_PORT)
    tornado.ioloop.IOLoop.instance().start()
