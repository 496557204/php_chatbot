FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV MYSQL_HOST=11.142.154.110 \
    MYSQL_PORT=3306 \
    MYSQL_DATABASE_NAME=ohvbkqek \
    MYSQL_USERNAME=with_ewjuocsrpdlllwld \
    MYSQL_PASSWORD=q)eeH@yf8OtB3p \
    SECRET_KEY=your_secure_secret_key_here

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
