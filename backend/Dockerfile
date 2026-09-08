FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir pip==26.2.1 && pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN groupadd --system agenttrust && useradd --system --gid agenttrust --home-dir /nonexistent agenttrust \
    && mkdir -p /app/data && chown -R agenttrust:agenttrust /app

USER agenttrust

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
