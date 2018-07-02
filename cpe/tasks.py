from __future__ import absolute_import, unicode_literals
from vms.celery import app
from celery.task.schedules import crontab
from celery import chord
from celery.decorators import periodic_task
from celery.utils.log import get_task_logger
from .utils import cpe_handler, Rpm
import datetime
from products.models import product,server
import csv
from cve.tasks import add_vulns
from io import StringIO
from notifications.models import notification
from django.contrib.auth.models import User
from cpe.models import template

logger = get_task_logger(__name__)

@periodic_task(
    run_every=crontab(minute=59, hour=15),
    name="CPE DB update",
    ignore_result=True
)
def update_cpe_db():
    logger.info("Starting CPE update")
    obj = cpe_handler()
    obj.update_db()
    logger.info("CPE update complete")

def get_template(template_name,cur_user):
    temp = None
    user = User.objects.get(id=cur_user)
    if template_name != '':
        if template.objects.filter(name=template_name).exists():
            num = 1
            new_name = template_name + '(' + str(num) + ')'
            while not template.objects.filter(new_name).exists():
                count = count + 1
                new_name = template_name + '(' + str(num) + ')'
            temp = template(name='new_name',user=user)
        else:
            temp = template(name=template_name,user=user)
        temp.save()
    return temp

@app.task
def add_cpe_from_csv(csv_file,cur_user,template_name):
    temp = get_template(template_name,cur_user)
    obj = cpe_handler()
    data = csv.reader(StringIO(csv_file))
    results = []
    success = []
    for row in data:
        ser = None
        pro = None
        if product.objects.filter(name=row[0],user=cur_user).exists():
            pro = product.objects.get(name=row[0],user=cur_user)
            if server.objects.filter(name=row[1],product=pro).exists():
                ser = server.objects.get(name=row[1],product=pro)
        for item in row[2:]:
            if item is '':
                continue
            if ser is not None and pro is not None:
                r = obj.add_cpe(item, ser.id)
                if r[0] == 0:
                    i = [pro.name,ser.name,item,"NA","Not found"]
                elif r[0] == -1:
                    if temp is not None:
                        obj.add_to_template(temp,item)
                    i = [pro.name,ser.name,item,r[1],"Already in DB"]
                else:
                    if temp is not None:
                        obj.add_to_template(temp,item)
                    i = [pro.name,ser.name,item,r[1],"Added to DB"]
                    success.append([item,ser.id])
            else:
                if pro is None:
                    i = [row[0],row[1],item,"NA","Product not found"]
                else:
                    i = [pro.name,row[1],item,"NA","Server not found"]
            results.append(i)
    add_vulns.delay(success,cur_user)

@app.task
def add_rpm(rpm_name,server_id,cur_user):
    rpm = Rpm()
    obj = cpe_handler()
    if rpm.set_rpm(rpm_name) is -1:
        return [rpm_name,"NA","NA","Invalid RPM name"]
    cpe_name = rpm.get_cpe()
    if len(cpe_name) > 1:
        return [rpm_name,"NA","NA","Multiple matches found"]
    elif len(cpe_name) == 1:
        cpe_name = cpe_name[0]
    results = []
    if cpe_name != []:
        r = obj.add_cpe(cpe_name,server_id)
        if r[0] == -1:
            return [rpm_name,cpe_name,r[1],"Already in DB"]
        elif r[0] == 1:
            return [rpm_name,cpe_name,r[1],"Added to DB"]
        else:
            return [rpm_name,cpe_name,"NA","Unknown error occured"]
    else:
        return [rpm_name,"NA","NA","No matching CPE found"]

@app.task
def chord_task(results,server_id,user_id,template_name):
    temp = get_template(template_name,user_id)
    obj = cpe_handler()
    args = []
    for item in results:
        if item[3] == "Added to DB" or item[3] == "Already in DB":
            args.append([item[1],server_id])
            if temp is not None:
                obj.add_to_template(temp,item[1])

    num = len(args)
    new_notif = notification(
        header=str(num) + " components have been added",
        message= str(num) + " components have been added to the database",
        user = User.objects.get(id=user_id),
        read = False)
    new_notif.save()
    add_vulns.delay(args,user_id)
    return results

@app.task
def add_rpm_from_file(rpm_list,server_id,user_id,template_name):
    task = chord(add_rpm.s(item.replace("\n",""),server_id,user_id) for item in rpm_list)(chord_task.s(server_id,user_id,template_name))
