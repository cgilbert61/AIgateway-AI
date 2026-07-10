FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt ./
COPY wheels ./wheels

RUN pip install --no-cache-dir --no-index --find-links=./wheels -r requirements.txt

COPY *.py ./

ENTRYPOINT ["python", "app.py"]
