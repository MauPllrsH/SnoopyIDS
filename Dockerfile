FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY certs/ca.crt certs/server.key certs/server.crt ./

EXPOSE 50051

CMD ["python", "app.py"]