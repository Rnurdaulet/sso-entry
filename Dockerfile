# Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Добавим поддержку .env
RUN pip install python-dotenv gunicorn

CMD ["gunicorn", "sso_project.wsgi:application", "-b", "0.0.0.0:8000"]
