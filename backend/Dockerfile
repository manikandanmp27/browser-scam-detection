FROM python:3.13-slim

WORKDIR /workspace

# Install system dependencies (build-essential, etc., if needed, though wheels don't require compile)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pre-train the ML model during build so it is ready inside the container
RUN python -m app.ml.train

EXPOSE 8000

ENV PORT=8000
ENV DATABASE_URL=sqlite:///./scam_detection.db

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
