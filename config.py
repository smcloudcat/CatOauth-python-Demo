# OAuth配置参数
CLIENT_ID = 'python-demo-app'
REDIRECT_URI = 'http://localhost:5000/callback'  # 本地开发回调地址

# 授权服务器端点URL
AUTHORIZATION_ENDPOINT = 'https://oauth.lwcat.cn/oauth/authorize'
TOKEN_ENDPOINT = 'https://oauth.lwcat.cn/oauth/token'
USERINFO_ENDPOINT = 'https://oauth.lwcat.cn/api/me'

# 请求的权限范围
SCOPE = 'profile email avatar username'
