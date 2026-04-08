FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy package source
COPY . .

EXPOSE 8000

ENV WORKERS=1
ENV PORT=8000
ENV HOST=0.0.0.0

CMD ["sh", "-c", "uvicorn ids_env.server.app:app --host $HOST --port $PORT --workers $WORKERS"]
