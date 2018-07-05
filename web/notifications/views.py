from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .models import notification

@login_required
def index(request):
    current_user = request.user
    new_notifs = notification.objects.filter(user=current_user,read=False)
    old_notifs = notification.objects.filter(user=current_user,read=True)
    context = {
        "unread": new_notifs,
        "read": old_notifs
    }
    for n in new_notifs:
        n.read = True
        n.save()
    return render(request, 'notifications/index.html',context)

@login_required
def get_notifications(request):
    if 'csrfmiddlewaretoken' not in request.POST:
        return index(request)
    current_user = request.user
    notifs = notification.objects.filter(user=current_user,read=False)
    count = len(notifs)
    if count > 4:
        notifs = notifs[:4]
    context = {
        "notifs": notifs,
        "count": count
    }
    return render(request, 'notifications/get.html',context)

@login_required
def clear_notifications(request):
    current_user = request.user
    new_notifs = notification.objects.filter(user=current_user).delete()
    return render(request, 'notifications/index.html')
