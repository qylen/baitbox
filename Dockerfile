FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose SSH (2222), HTTP honeypot (8080), Dashboard (8000)
EXPOSE 2222 8080 8000

CMD ["python", "-m", "baitbox.main"]
