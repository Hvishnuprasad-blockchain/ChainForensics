FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

RUN pip install --no-cache-dir \
    numpy \
    scipy \
    pandas \
    scikit-learn \
    joblib

COPY . .

RUN mkdir -p /app/models /app/logs

CMD ["python", "-m", "chainforensics.cli", "--help"]