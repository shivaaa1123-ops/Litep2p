FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY server.py /app/server.py

ENV PYTHONUNBUFFERED=1
ENV SIGNALING_HOST=0.0.0.0
ENV SIGNALING_PORT=8765
ENV LOG_LEVEL=INFO

EXPOSE 8765

CMD ["python", "/app/server.py"]


