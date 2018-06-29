from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .utils import cpe_handler
from io import TextIOWrapper
from .models import component,component_to_server
from products.models import server,product
from django.db.models import F
from django.http import JsonResponse,HttpResponse
from .tasks import add_cpe_from_csv,add_rpm_from_file,add_rpm
from cve.tasks import add_vulns
from vms.settings import USE_ELASTIC_SEARCH

@login_required
def index(request):
    context = {}
    if 'selected_cpe' in request.POST:
        for i in request.POST.getlist('selected_cpe'):
            if component_to_server.objects.filter(id=i).exists():
                component_to_server.objects.get(id=i).delete()
        context['deleted'] = True
        context['message'] = "Selected Items were deleted."
    product_list = product.objects.filter(user=request.user)
    context['products'] = product_list
    return render(request, 'cpe/index.html', context)

@login_required
def add_cpe(request):
    if 'cpe' in request.POST:
        if 'cpe:' in request.POST["cpe"]:
            obj = cpe_handler()
            r = obj.add_cpe(request.POST['cpe'],int(request.POST['server']))
            if r[0] == 0:
                return JsonResponse({"message": "Component not found!","type":"danger"})
            elif r[0] ==-1:
                return JsonResponse({"message": "Component already in database!","type":"warning"})
            elif r[0] ==-2:
                return JsonResponse({"message": "Unknown error occured","type":"danger"})
            else:
                add_vulns.delay([[request.POST['cpe'],int(request.POST['server'])]],request.user.id)
                return JsonResponse({"message": "Component added successfully!","type":"success"})
        else:
            r = add_rpm(request.POST['cpe'],int(request.POST['server']),request.user)
            if r[3] == "Invalid RPM name":
                return JsonResponse({"message": "Invalid input!","type":"danger"})
            elif r[3] == "Already in DB":
                return JsonResponse({"message": "Component already in database!","type":"warning"})
            elif r[3] == "Unknown error occured":
                return JsonResponse({"message": r[3],"type":"danger"})
            elif r[3] == "Added to DB":
                return JsonResponse({"message": "Component added successfully!","type":"success"})
            elif r[3] == "Multiple matches found":
                return JsonResponse({"message": r[3],"type":"warning"})
            else:
                return JsonResponse({"message": "Component not found","type":"danger"})

    elif 'file_location' in request.FILES:
        if request.POST["filetype"] == "csv":
            csv_file = TextIOWrapper(request.FILES['file_location'].file, encoding=request.encoding)
            add_cpe_from_csv.delay(csv_file.read(),request.user.id)
            return HttpResponse("Adding the components. Please Wait..")
        elif request.POST["filetype"] == "rpm":
            rpm_file = TextIOWrapper(request.FILES['file_location'].file, encoding=request.encoding)
            rpm_list = rpm_file.readlines()
            add_rpm_from_file.delay(rpm_list,int(request.POST["server"]),request.user.id)
            return HttpResponse("RPMs are bing added. Please wait.")
        else:
            return HttpResponse("Unknown Error occured!")
    else:
        return HttpResponse("Unknown Error occured!")

@login_required
def get_dropdown(request):
    context = {}
    if 'csrfmiddlewaretoken' in request.POST:
        server_list = server.objects.filter(product__id=int(request.POST['product']))
        context['servers'] = server_list
        return render(request, 'cpe/get_dropdown.html',context)
    else:
        return index(request)

@login_required
def get_table(request):
    cpe_list = component_to_server.objects.filter(server__product__user=request.user).annotate(
        server_name=F('server__name'),
        product_name=F('server__product__name'),
        cpe_id=F('cpe__cpe_id'),
        title=F('cpe__title')
    )
    result = []
    for item in cpe_list:
        row = []
        row.append("<input type='checkbox' name='selected_cpe' value=" + str(item.id) + " class='cpe-radio'/>")
        row.append(item.product_name)
        row.append(item.server_name)
        row.append(item.cpe_id)
        row.append(item.title)
        result.append(row)
    return JsonResponse({"data":result}, safe=False)

@login_required
def add_from_template(request):
    products = product.objects.filter(user=request.user)
    return render(request,'cpe/add_from_template.html',{"products": products})

@login_required
def autocomplete(request):
    response = []
    if 'search' in request.GET and request.GET['search'] is not '':
        data = component.objects.filter(title__icontains=request.GET['search'])
        for item in data:
            response.append({"name": item.title,"id": item.id})
        return JsonResponse(response, safe=False)
    elif 'searchall' in request.GET and request.GET['searchall'] is not '':
        if USE_ELASTIC_SEARCH:
            from elasticsearch import Elasticsearch
            es = Elasticsearch()
            query = {"query" : {"match":{"title": request.GET['searchall']}}}
            res = es.search(index="cpe-names",body=query,size=100)
            for item in res["hits"]["hits"]:
                response.append({"name": item["_source"]["title"],"cpe": item["_source"]["cpe_id"],"id": 0})
    return JsonResponse(response, safe=False)
