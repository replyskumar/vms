from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required
def home(request):
    return render(request, 'home/index.html')

@login_required
def profile(request):
    context = {
        'username': request.user.username,
        'first_name': request.user.first_name,
        'last_name': request.user.last_name,
        'email': request.user.email
    }
    return render(request, 'user/profile.html',context)

@login_required
def accountmanager(request):
    if 'old_password' in request.POST and 'new_password' in request.POST and 'new_password_again' in request.POST:
        old_pass = request.POST['old_password']
        new_pass = request.POST['new_password']
        new_pass2 = request.POST['new_password_again']
        if request.user.check_password(old_pass):
            if new_pass == new_pass2:
                if len(new_pass) > 8:
                    request.user.set_password(new_pass)
                    return render(request, 'user/update.html',{'password':True})
                else:
                    return render(request, 'user/update.html',{'weak':True})
            else:
                return render(request, 'user/update.html',{'mismatch':True})
        else:
            return render(request, 'user/update.html',{'wrongpassword':True})
    elif request.POST['userid']:
        username = request.POST['userid']
        fname = request.POST['first_name']
        lname = request.POST['last_name']
        email = request.POST['email']
        if fname is not "" and lname is not "" and email is not "":
            request.user.first_name = fname
            request.user.last_name = lname
            request.user.email = email
            request.user.save()
            return render(request, 'user/update.html',{'update':True})
        else:
            return render(request, 'user/update.html',{'emptyfield':True})
    else:
        return profile(request)
