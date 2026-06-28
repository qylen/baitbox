FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose SSH (2222), Telnet (2323), Dashboard + HTTP honeypot (8000)
EXPOSE 2222 2323 8000

# Persist database across container restarts
VOLUME ["/data"]
ENV BAITBOX_DB=/data/baitbox.db

CMD ["python", "-m", "baitbox.main"]
