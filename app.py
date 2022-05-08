from flask import Flask, render_template, jsonify, request, redirect, url_for
from pymongo import MongoClient
from bson.objectid import ObjectId
import jwt
import hashlib
import datetime

app = Flask(__name__)
client = MongoClient('localhost', 27017)
db = client.dbtime

# JWT
SECRET_KEY = "TIMEATTACK"


# 1. 토큰이 유효하다면 {html}로 user의 email을 전송하며 render_template
# 2. 토큰이 유효하지 않다면 login.html로 이동
def check_token(html):
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user = db.users.find_one({'_id': ObjectId(payload['id'])})
        if user is not None:
            if html == 'login.html':
                return redirect(url_for('index', email=user['email']))
            return render_template(html, email=user['email'])

    except jwt.ExpiredSignatureError:
        return render_template('login.html', msg='로그인 만료')
    except jwt.exceptions.DecodeError:
        return render_template('login.html')


# 메인
@app.route('/')
def index():
    return check_token('index.html')


# 로그인
@app.route('/login')
def login():
    return check_token('login.html')


# 회원가입
@app.route('/signup')
def signup():
    return check_token('signup.html')


# 로그인 API
@app.route("/api/login", methods=['POST'])
def login_proc():
    email = request.form['email_give']
    password = request.form['pw_give']
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()

    user = db.users.find_one({'email': email, 'password': hashed_pw})

    if user is not None:
        payload = {'id': str(user['_id']),
                   'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=1800)}

        return jsonify({
            'result': 'success',
            'token': jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        })
    else:
        return jsonify({'result': 'fail', 'msg': '이메일 또는 비밀번호를 잘못 입력하였습니다.'})


# 로그아웃 API
@app.route("/api/logout", methods=['GET'])
def logout_proc():
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        return jsonify({
            'result': 'success',
            'token': jwt.encode(payload, SECRET_KEY, algorithm='HS256'),
            'msg': '로그아웃 성공'
        })
    except jwt.ExpiredSignatureError or jwt.exceptions.DecodeError:
        return jsonify({
            'result': 'fail',
            'msg': '로그아웃 실패'
        })


# 회원가입 API
@app.route('/api/signup', methods=['POST'])
def signup_proc():
    user = db.users.find_one({'email': request.form['email_give']})
    if user is not None:
        return jsonify({'result': 'duplication', 'msg': '중복 이메일'})
    else:
        password = request.form['pw_give']
        hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
        doc = {
            'email': request.form['email_give'],
            'password': hashed_pw
        }
        db.users.insert_one(doc)
        return jsonify({'result': 'success', 'msg': '회원가입 성공'})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
