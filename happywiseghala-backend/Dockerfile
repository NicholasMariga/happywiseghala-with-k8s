FROM python:3.11-slim

WORKDIR /app

RUN pip install flask flask-cors psycopg2-binary openpyxl groq --no-cache-dir

COPY app.py .

EXPOSE 5000

CMD ["python", "app.py"]
