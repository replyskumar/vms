from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import affects
from django.db.models import F
from django.http import HttpResponse, JsonResponse
from products.models import product
from datetime import datetime
from cpe.models import component_to_server,component
from vms.settings import USE_ELASTIC_SEARCH

@login_required
def index(request,error=False):
    product_list = product.objects.filter(user=request.user)
    context = {'products': product_list}
    if error is True:
        context['error'] = True
    return render(request, 'cve/index.html', context)

@login_required
def get_vuln(request):
    if 'affect-id' in request.POST:
        context = {}
        if affects.objects.filter(id=float(request.POST['affect-id']),server__product__user=request.user).exists():
            results = affects.objects.filter(id=float(request.POST['affect-id']),server__product__user=request.user).annotate(
                vuln_cve=F('cve__cve_id'),
                product_name=F('server__product__name'),
                server_name=F('server__name'),
                component_name=F('c2s__cpe__cpe_id'),
                component_title=F('c2s__cpe__title'),
                summary=F('cve__summary'),
                published=F('cve__published'),
                last_modified=F('cve__last_modified'),
                in_date=F('cve__in_date'),
                score_v3=F('cve__score_v3'),
                vector_sting_v3=F('cve__vector_string_v3'),
                score_v2=F('cve__score_v2'),
                vector_sting_v2=F('cve__vector_string_v2')
                )
            context['results'] = results[0]
        print(context)
        return render(request, 'cve/get_vuln.html', context)
    return index(request)

@login_required
def update_vuln(request):
    if 'affect-id' in request.POST:
        if affects.objects.filter(id=float(request.POST['affect-id']),server__product__user=request.user).exists():
            obj = affects.objects.get(id=float(request.POST['affect-id']),server__product__user=request.user)
            obj.comments = request.POST["comments"]
            obj.custom_score = request.POST["custom_score"]
            obj.save()
            return HttpResponse("Successfully updated!")
        else:
            return HttpResponse("Unknown error occured!")
    else:
        return index(request)

@login_required
def query_vuln(request):
    print(request.POST)
    try:
        datetime.strptime(request.POST['from_date'], "%Y-%m-%d")
        datetime.strptime(request.POST['to_date'], "%Y-%m-%d")
    except ValueError:
        return index(request,error=True)
    if 'product' in request.POST:
        context = {}
        try:
            if request.POST['product'] is '':
                vuln_list = affects.objects.filter(server__product__user=request.user,cve__published__range=[request.POST['from_date'],request.POST['to_date']]).annotate(
                    product_name=F('server__product__name'),
                    server_name=F('server__name'),
                    component_name=F('c2s__cpe__cpe_id'),
                    component_title=F('c2s__cpe__title'),
                    vuln_cve=F('cve__cve_id'),
                    score_v3=F('cve__score_v3'),
                    score_v2=F('cve__score_v2'),
                    published=F('cve__published')
                )
                context['header'] = 'All Products'
            else:
                vuln_list = affects.objects.filter(server__product__user=request.user,server__product__id=request.POST['product'],cve__published__range=[request.POST['from_date'],request.POST['to_date']]).annotate(
                    product_name=F('server__product__name'),
                    server_name=F('server__name'),
                    component_name=F('c2s__cpe__cpe_id'),
                    component_title=F('c2s__cpe__title'),
                    vuln_cve=F('cve__cve_id'),
                    score_v3=F('cve__score_v3'),
                    score_v2=F('cve__score_v2'),
                    published=F('cve__published')
                )
                context['header'] = product.objects.get(id=request.POST['product']).name
            context['results'] = vuln_list
            return render(request, 'cve/query.html', context)
        except:
            return index(request,error=True)
    elif 'cpe' in request.POST:
        context = {}
        if request.POST['cpe'] is '':
            return index(request,error=True)
        vuln_list = affects.objects.filter(server__product__user=request.user,cve__published__range=[request.POST['from_date'],request.POST['to_date']],c2s__cpe__id=request.POST['cpe']).annotate(
            product_name=F('server__product__name'),
            server_name=F('server__name'),
            component_name=F('c2s__cpe__cpe_id'),
            component_title=F('c2s__cpe__title'),
            vuln_cve=F('cve__cve_id'),
            score_v3=F('cve__score_v3'),
            score_v2=F('cve__score_v2'),
            published=F('cve__published')
        )
        context['header'] = component_to_server.objects.get(id=request.POST["cpe"]).cpe.title
        context['results'] = vuln_list
        context['product'] = True
        return render(request, 'cve/query.html', context)
    else:
        return index(request)
