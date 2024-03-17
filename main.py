from flask import Flask, jsonify, request, make_response
import jwt 
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'oQpvCDuuITsDKyVpqKgREdQrRjFYzDGG'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403

        try: 
            token_type, token_value = token.split()
            if token_type != 'Bearer':
                raise ValueError("Invalid token type")
                
            data = jwt.decode(token_value, app.config['SECRET_KEY'], algorithms=["HS256"])
        except Exception:
            return jsonify({'message' : 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated

@app.route('/protected')
@token_required
def protected():
    return jsonify({'message' : 'This is only available for people with valid tokens.'})

@app.route('/login')
def login():
    auth = request.authorization

    if auth and auth.username == '' and auth.password == '':
        token = jwt.encode({'logged_in' : True, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token' : token})

    return make_response('Could not verify!', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})

if __name__ == "__main__":
    app.run(debug=True)
