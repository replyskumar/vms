from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import F
from products.models import product,server
from django.http import HttpResponse,JsonResponse
from django.db.models import Count
import csv
from io import TextIOWrapper

# Create your views here.
@login_required
def index(request):
    context = {}
    if 'selected_products' in request.POST:
        for pid in request.POST.getlist("selected_products"):
            if product.objects.filter(id=pid).exists():
                product.objects.filter(id=pid).delete()
        context["deleted"] = True
        context["message"] = str(len(request.POST["selected_products"])) + ' products have been deleted!'
    return render(request, 'products/index.html', context)

@login_required
def add_product(request):
    if 'product' in request.POST:
        if product.objects.filter(name=request.POST['product']).exists():
            return HttpResponse("Product with the same name already exists!")
        else:
            pro = product(name=request.POST['product'],user=request.user)
            pro.save()
            return HttpResponse("Product has been added!")
    else:
        return index(request)

@login_required
def servers(request):
    product_list = product.objects.filter(user=request.user)
    context = {'products': product_list}
    if 'selected_servers' in request.POST:
        for sid in request.POST.getlist("selected_servers"):
            if server.objects.filter(id=sid).exists():
                server.objects.filter(id=sid).delete()
        context["deleted"] = True
        context["message"] = 'Selected servers have been deleted!'
    return render(request, 'products/server.html', context)

@login_required
def add_server(request):
    if 'server' in request.POST and 'product' is not '':
        pro = product.objects.get(id=request.POST['product'])
        if server.objects.filter(name=request.POST['server'],product=pro).exists():
            return HttpResponse("Server with the same name already exists!")
        else:
            ser = server(name=request.POST['server'],product=pro)
            ser.save()
            return HttpResponse("Server has been added!")
    elif 'file_location' in request.FILES:
        csv_file = TextIOWrapper(request.FILES['file_location'].file, encoding=request.encoding)
        data = csv.reader(csv_file)
        results = []
        for row in data:
            pro = None
            if product.objects.filter(name=row[0],user=request.user).exists():
                pro = product.objects.get(name=row[0],user=request.user)
            for item in row[1:]:
                if item is '':
                    continue
                if pro is not None:
                    if server.objects.filter(product=pro,name=item).exists():
                        i = [pro.name,item,"Server with same name exists"]
                    else:
                        ser = server(name=item,product=pro)
                        ser.save()
                        i = [pro.name,item,"Added to DB"]
                else:
                    i = [row[0],item,"Product not found"]
                results.append(i)
        context = {"results": results}
        return render(request, 'products/add_multiple.html', context)
    else:
        return index(request)

def get_table(request):
    if 'server' in request.GET:
        server_list = server.objects.filter(product__user=request.user).annotate(product_name=F('product__name'), cpe_count=Count('component_to_server'))
        result = []
        for item in server_list:
            row = []
            row.append("<input type='checkbox' name='selected_servers' value=" + str(item.id) + " class='servers-radio'/>")
            row.append(item.id)
            row.append(item.name)
            row.append(item.product_name)
            row.append(item.cpe_count)
            result.append(row)
        return JsonResponse({"data": result})
    elif 'product' in request.GET:
        product_list = product.objects.filter(user=request.user).annotate(server_count=Count('server'))
        result = []
        for item in product_list:
            row = []
            row.append("<input type='checkbox' name='selected_products' value=" + str(item.id) + " class='products-radio'/>")
            row.append(item.id)
            row.append(item.name)
            row.append(item.server_count)
            result.append(row)
        return JsonResponse({"data": result})
    else:
        return render(request,"home/index.html")
