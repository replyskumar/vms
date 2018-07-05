FROM alpine

COPY requirements.txt /

# Setup
ARG HTTP_PROXY=http://10.53.130.55:8080/
ARG HTTPS_PROXY=http://10.53.130.55:8080/
RUN apk update
RUN apk upgrade
RUN apk add --update python3 python3-dev postgresql-client postgresql-dev build-base gettext
RUN pip3 install --upgrade pip
RUN pip3 install -r /requirements.txt
RUN mkdir -p /var/logs/
COPY celery_start.sh /
RUN chmod +x /celery_start.sh

# Clean
RUN apk del -r python3-dev postgresql
