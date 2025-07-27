# 如何启动服务
## 正常启动
### 安装Python依赖
pip install -r requirements.txt

### 设置环境变量
export MYSQL_HOST=11.142.154.110
export MYSQL_PORT=3306
export MYSQL_DATABASE_NAME=ohvbkqek
export MYSQL_USERNAME=with_ewjuocsrpdlllwld
export MYSQL_PASSWORD="q)eeH@yf8OtB3p"
export SECRET_KEY=your_secure_secret_key_here

### 启动后端服务
uvicorn main:app --host 0.0.0.0 --port 8000

## denbug模式启动
### 安装依赖
pip install -r requirements.txt
### 设置环境变量
export MYSQL_HOST=62.234.187.52
export MYSQL_PORT=3306
export MYSQL_DATABASE_NAME=test
export MYSQL_USERNAME=mytest
export MYSQL_PASSWORD="Test@123"
export SECRET_KEY=your_secure_secret_key_here
### 启动后端服务（调试模式） 启用热加载
uvicorn main:app --reload --host 0.0.0.0 --port 8000


# api文档查看：





