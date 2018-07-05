from __future__ import absolute_import, unicode_literals
from vms.celery import app
from celery.task.schedules import crontab
from celery.decorators import periodic_task
from celery.utils.log import get_task_logger
from celery import chord,group,chain
from .utils import cve_handler,CACHE_PATH,match_cpe
import datetime
from notifications.models import notification
from django.contrib.auth.models import User
try:
    from cPickle import load, PickleError, dump, HIGHEST_PROTOCOL
except ImportError:
    from pickle import load, PickleError, dump, HIGHEST_PROTOCOL
from .models import vulnerability,affects
from cpe.models import component,component_to_server
from os import path
from django.db.models import F

logger = get_task_logger(__name__)

@app.task
def vulns_added_notif(num,cur_user):
    new_notif = notification(
        header=str(num) + " new component vulns processed",
        message="Vulnerabilities for " + str(num) + " components have been processed",
        user = User.objects.get(id=cur_user),
        read = False)
    new_notif.save()

@app.task
def add_vulns(cpe_names, cur_user):
    task = chord(add_vuln.si(item) for item in cpe_names)(vulns_added_notif.si(len(cpe_names),cur_user))

@app.task
def add_vuln(item):
    obj = cve_handler()
    obj.add_cve(item[0],item[1])
    print("Added vulns for ",item[0])

@app.task
def update_cve_db_year(year):
    obj = cve_handler()
    obj.update_db(year)
    logger.info("CVE db of " + str(year) + " updated")

@periodic_task(
    run_every=crontab(minute=0, hour=0),
    name="CVE DB update",
    ignore_result=True
)
def update_cve_db():
    now = datetime.datetime.now()
    tasks = []
    task = chain(update_cve_db_year.si(str(year)) for year in range(2002,int(now.year) + 1))()

@periodic_task(
    run_every=crontab(minute=0, hour=0),
    name="CVE daily update",
    ignore_result=True
)
def get_daily_update():
    task = chain(update_cve_db_year.si('modified'),get_modifications.si())()

@app.task
def get_modifications():

    try:
        modified_items = load(open(path.join(CACHE_PATH,'modified.db'), "rb"))
    except PickleError as e:
        print("Error while loading CVE database. Error: %s." % e.message)
        return
    for item in modified_items:
        temp = vulnerability(
            cve_id = item.id,
            summary = item.summary,
            published = item.published,
            last_modified = item.last_modified,
            score_v2 = item.cvss.get('score_v2',0),
            score_v3 = item.cvss.get('score_v3',0),
            vector_string_v2 = item.cvss.get('vector_string_v2','NA'),
            vector_string_v3 = item.cvss.get('vector_string_v3','NA'),
        )
        if vulnerability.objects.filter(cve_id=item.id).exists():
            vuln = vulnerability.objects.get(cve_id=item.id)
            vuln.summary = temp.summary
            vuln.last_modified = temp.last_modified
            vuln.score_v2 = temp.score_v2
            vuln.score_v3 = temp.score_v3
            vuln.vector_string_v2 = temp.vector_string_v2
            vuln.vector_string_v3 = temp.vector_string_v3
            vuln.save()
            for rel in affects.objects.filter(cve=vuln).annotate(cpe_id=F('c2s__cpe__cpe_id')):
                for comp in item.affected:
                    if match_cpe(rel.cpe_id,comp['cpe22'],comp):
                        if comp['vuln'] is False:
                            affects.objects.filter(id=rel.id).delete()
        else:
            for comp in item.affected:
                if comp['vuln'] is True:
                    if component.objects.filter(cpe_id__contains=comp['cpe22']).exists():
                        temp.save()
                        for c2s in component_to_server.objects.filter(cpe__cpe_id__contains=comp['cpe22']):
                            if match_cpe(c2s.cpe.cpe_id,comp['cpe22'],comp):
                                if not affects.objects.filter(c2s=c2s,cve=temp,server=c2s.server).exists():
                                    rel = affects(c2s=c2s,cve=temp,server=c2s.server,custom_score=0)
                                    rel.save()
