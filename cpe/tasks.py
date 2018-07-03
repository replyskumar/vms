from __future__ import absolute_import, unicode_literals
from vms.celery import app
from celery.task.schedules import crontab
from celery import chord
from celery.decorators import periodic_task
from celery.utils.log import get_task_logger
from .utils import cpe_handler, Rpm, add_to_template,get_template
import datetime
from products.models import product,server
import csv
from cve.tasks import add_vulns
from io import StringIO
from notifications.models import notification
from django.contrib.auth.models import User

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

@app.task
def add_cpe(item,server_id,product_id,cur_user):

    if product_id == -1:
        return ["NA","NA",item,"NA","Product not found"]
    pro = product.objects.get(id=product_id,user=cur_user)
    if server_id == -1:
        return [pro.name,"NA",item,"NA","Server not found"]
    ser = server.objects.get(id=server_id,product=pro)

    obj = cpe_handler()
    r = obj.add_cpe(item,server_id)
    if r[0] == 0:
        return [pro.name,ser.name,item,"NA","Not found"]
    elif r[0] == -1:
        return [pro.name,ser.name,item,r[1],"Already in DB",server_id]
    else:
        return [pro.name,ser.name,item,r[1],"Added to DB",server_id]

@app.task
def update_cpe(id,item,server_id,product_id,cur_user):

    if product_id == -1:
        return ["NA","NA",item,"NA","Product not found"]
    pro = product.objects.get(id=product_id,user=cur_user)
    if server_id == -1:
        return [pro.name,"NA",item,"NA","Server not found"]
    ser = server.objects.get(id=server_id,product=pro)

    if id == 0:
        obj = cpe_handler()
        r = obj.add_cpe(item,server_id)
        if r[0] == 0:
            return [pro.name,ser.name,item,"NA","Not found"]
        elif r[0] == -1:
            return [pro.name,ser.name,item,r[1],"Already in DB",server_id]
        else:
            return [pro.name,ser.name,item,r[1],"Added to DB",server_id]
    else:
        c2s = component_to_server.objects.get(id=id)
        cpe = c2s.cpe


@app.task
def cpe_chord_task(results,user_id,template_name):
    obj = cpe_handler()
    temp = get_template(template_name,user_id)
    args = []
    for item in results:
        if item[4] == "Added to DB" or item[4] == "Already in DB":
            args.append([item[2],item[5]])
            if temp is not None:
                add_to_template(temp,item[2])

    num = len(args)
    new_notif = notification(
        header=str(num) + " components have been added",
        message= str(num) + " components have been added to the database",
        user = User.objects.get(id=user_id),
        read = False)
    new_notif.save()
    add_vulns.delay(args,user_id)
    return results


def yield_cpe_from_csv(data,cur_user):
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
                yield item, ser.id, pro.id
            elif pro is None:
                yield item, -1, -1
            else:
                yield item, -1, pro.id


@app.task
def add_cpe_from_csv(csv_file,cur_user,template_name):
    obj = cpe_handler()
    data = csv.reader(StringIO(csv_file))
    task = chord(add_cpe.s(item,ser_id,pro_id,cur_user) for item,ser_id,pro_id in yield_cpe_from_csv(data,cur_user))(cpe_chord_task.s(cur_user,template_name))

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
def rpm_chord_task(results,server_id,user_id,template_name=''):
    temp = get_template(template_name,user_id)
    obj = cpe_handler()
    args = []
    for item in results:
        if item[3] == "Added to DB" or item[3] == "Already in DB":
            args.append([item[1],server_id])
            if temp is not None:
                add_to_template(temp,item[1])

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
def add_rpm_from_file(rpm_list,server_id,user_id,template_name=''):
    task = chord(add_rpm.s(item.replace("\n",""),server_id,user_id) for item in rpm_list)(rpm_chord_task.s(server_id,user_id,template_name))
