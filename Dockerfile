FROM python:3.10.4
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY webserver.py .
COPY web_resources ./web_resources
CMD gunicorn webserver:start --bind 0.0.0.0:8080 --worker-class aiohttp.GunicornWebWorker