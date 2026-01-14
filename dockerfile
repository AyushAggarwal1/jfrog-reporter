FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY . /app/
# Install dependencies
RUN pip3 install -r requirements.txt --no-cache-dir

# Prepare output directory
RUN mkdir -p /app/report_output

# JFROG_URL, JFROG_API_KEY, and JFROG_REPO must be provided at runtime
ENTRYPOINT ["python3", "jfrog_report.py"]
