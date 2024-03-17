from flask import Flask, jsonify, request
import jwt 
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'oQpvCDuuITsDKyVpqKgREdQrRjFYzDGG'

# Kullanıcı bilgileri (gerçek uygulamada veritabanından alınır)
users = {
    'user1': 'password1',
    'user2': 'password2'
}

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

@app.route('/api/v1/login', methods=['POST'])
def login():
    auth = request.json

    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Kullanıcı adı ve parola gereklidir'}), 401

    username = auth['username']
    password = auth['password']

    if username not in users or users[username] != password:
        return jsonify({'message': 'Geçersiz kullanıcı adı veya parola'}), 401
    
    # Başarılı giriş işlemi sonrasında JWT token oluşturulur
    token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'])
    return jsonify({'token': token})

@app.route('/api/v1/protected')
@token_required
def protected():
    return jsonify({'message' : 'This is only available for people with valid tokens.'})

if __name__ == "__main__":
    app.run(debug=True)
