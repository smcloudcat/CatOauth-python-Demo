from flask import Flask, session, redirect, url_for, request, render_template
import requests
import os
import json
from config import CLIENT_ID, REDIRECT_URI, AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, USERINFO_ENDPOINT, SCOPE

app = Flask(__name__)
app.secret_key = os.urandom(24)  # 生成安全的密钥

@app.route('/')
def index():
    # 检查session中是否有用户信息
    if 'user_info' in session:
        return redirect(url_for('user_info'))
    
    # 生成state参数防止CSRF攻击
    state = os.urandom(16).hex()
    session['oauth2_state'] = state
    
    # 构建授权URL
    auth_url = f"{AUTHORIZATION_ENDPOINT}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={state}"
    
    return render_template('index.html', authorization_url=auth_url)

@app.route('/callback')
def callback():
    # 验证state参数
    if 'oauth2_state' not in session or request.args.get('state') != session['oauth2_state']:
        session.pop('oauth2_state', None)
        return '无效的state参数，可能存在CSRF攻击。', 400
    
    # 检查是否收到code
    if 'code' not in request.args:
        if 'error' in request.args:
            return f"授权失败: {request.args.get('error')} - {request.args.get('error_description')}", 400
        return '未收到授权码(code)。', 400
    
    code = request.args.get('code')
    
    try:
        # 使用code换取access_token
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID
        }
        token_response = requests.post(TOKEN_ENDPOINT, data=token_data, headers={'Accept': 'application/json'})
        token_response.raise_for_status()
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            return '响应中未包含access_token。', 400
        
        access_token = token_json['access_token']
        
        # 使用access_token获取用户信息
        user_response = requests.get(USERINFO_ENDPOINT, headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        })
        user_response.raise_for_status()
        user_info = user_response.json()
        
        # 存储用户信息到session
        session['user_info'] = user_info
        session['access_token'] = access_token
        
        return redirect(url_for('user_info'))
    
    except requests.exceptions.RequestException as e:
        return f'请求失败: {str(e)}', 500

@app.route('/user_info')
def user_info():
    # 检查用户是否已登录
    if 'user_info' not in session:
        return redirect(url_for('index'))
    
    user_info = session['user_info']
    access_token = session.get('access_token', '')
    
    return render_template('user_info.html', 
                          user_info=user_info, 
                          access_token=access_token,
                          json_user_info=json.dumps(user_info, indent=2, ensure_ascii=False))

@app.route('/logout')
def logout():
    # 清除session
    session.pop('user_info', None)
    session.pop('access_token', None)
    session.pop('oauth2_state', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
