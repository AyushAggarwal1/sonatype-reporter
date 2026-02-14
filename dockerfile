FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY . /app/
# Install dependencies
RUN pip3 install -r requirements.txt --no-cache-dir

# Prepare output directory
RUN mkdir -p /app/sonatype-reports
RUN mkdir -p /app/sarif-reports

# base_url, user_id, api_key, application, convert_to_sarif must be provided at runtime
ENTRYPOINT ["python3", "sonatype.py"]
