#!/bin/sh -ex
celery -A vms worker -l info --workdir /data/web -f /var/logs/celery.log &
celery -A vms beat -l info --workdir /data/web -f /var/logs/celerybeat.log &
tail -f /dev/null
