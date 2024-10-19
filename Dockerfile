FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY ssl/ca.crt ssl/ids_server.key ssl/ids_server.crt ./

EXPOSE 50051

CMD ["python", "app.py"]