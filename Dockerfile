FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY . .

ENV PORT=5000
EXPOSE 5000

CMD ["sh", "-c", "gunicorn backend.app:app --bind 0.0.0.0:${PORT} --workers 2 --threads 4 --timeout 120"]
