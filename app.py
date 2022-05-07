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


# 1. 로그인 / 회원가입에 사용
# 2. 토큰이 유효하다면 로그인/회원가입의 접근을 차단하고 index.html로 해당 토큰 주인의 이메일 주소를 전달하며 이동
# 3. 토큰이 유효한게 아니라면 {html}로 이동
def check_token_auth(html):
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user = db.users.find_one({'_id': ObjectId(payload['id'])})
        if user is not None:
            return render_template('index.html', email=user['email'])
    finally:
        return render_template(html)


# 1. 토큰이 유효하다면 {target_html}에 해당 토큰 주인의 이메일 주소를 전달하며 이동
# 2. 토큰 정보의 사용자가 존재하지 않는다면 로그인 화면으로 이동
# 3. 토큰이 만료됐거나 유효하지 않다면 로그인 화면으로 redirect (except)
def check_token_common(target_html):
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user = db.users.find_one({'_id': ObjectId(payload['id'])})
        if user is not None:
            return render_template(target_html, email=user['email'])
        else:
            return render_template('login.html')
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.DecodeError:
        return redirect(url_for('login'))


# 메인
@app.route('/')
def index():
    return check_token_common('index.html')


# 로그인
@app.route('/login')
def login():
    return check_token_auth('login.html')


# 회원가입
@app.route('/signup')
def signup():
    return check_token_auth('signup.html')


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
