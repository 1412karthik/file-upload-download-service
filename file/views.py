from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.contrib.auth.models import User
from .models import File
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.paginator import Paginator
from django.contrib.auth import login, logout
from django.views.static import serve
import os
from .serializers import UserSerializer, FileSerializer
from rest_framework.authtoken.models import Token
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated


def home(request):
    if request.user.is_authenticated:
        token = Token.objects.get_or_create(user=request.user)
        user = User.objects.get(username=request.user.username)
        files = user.files.all()
        paginator = Paginator(files, 5)
        page = request.GET.get('page')
        if bool(files):
            files = paginator.get_page(page)
            context = {'paginator': paginator,
                       'files': files,
                       'user': user,
                       'token_user': token[0].user,
                       'token_key': token[0].key, }
            return render(request, 'file/home.html', context, status=200)
        else:
            context = {'warn_msg': '''You haven't Uploaded any
                                Files just upload some files to access it''',
                       'token_user': token[0].user,
                       'token_key': token[0].key, }
            return render(request, 'file/home.html', context, status=200)
    else:
        return HttpResponseRedirect("/login")


def log_in(request):
    if request.user.is_authenticated:
        return HttpResponseRedirect("/")
    else:
        if request.method == 'GET':
            form = AuthenticationForm()
            return render(request, 'file/login.html', {'form': form}, status=200)
        elif request.method == 'POST':
            form = AuthenticationForm(data=request.POST)
            if form.is_valid():
                login(request, form.get_user())
                return HttpResponseRedirect("/")
            else:
                return render(request, 'file/login.html', {'form': form}, status=200)
        else:
            return HttpResponse("Unsupported method Please use GET or POST ", status=405)


def upload(request):
    if request.user.is_authenticated:
        if request.method == 'GET':
            return render(request, 'file/upload.html', status=200)
        if request.method == 'POST':
            try:
                file_name, file_path = handle_uploaded_file(request, request.FILES['file'], str(request.FILES['file']))
                file = File(name=file_name, user=request.user, path=file_path)
                file.save()
                return HttpResponseRedirect("/")
            except KeyError:
                return HttpResponseRedirect("/upload")
            except ValueError:
                return HttpResponse("File Already Exists", status=400)
        else:
            return HttpResponse("Unsupported method Please use GET or POST ", status=405)
    else:
        return HttpResponseRedirect("/login")


def handle_uploaded_file(request, file, filename):
    user_name = request.user.username
    path = 'upload/{}/'.format(request.user.username) + filename
    if os.path.exists(path):
        return HttpResponse("File Already Exists", status=200)
    if not os.path.exists('upload/'):
        os.mkdir('upload/')
    if not os.path.exists('upload/{}/'.format(user_name)):
        os.mkdir('upload/{}/'.format(user_name))
    with open(path, 'wb+') as destination:
        for chunk in file.chunks():
            destination.write(chunk)
    abs_path = os.path.abspath(path)
    return filename, abs_path


def signup(request):
    if request.method == 'GET':
        form = UserCreationForm()
        return render(request, 'file/signup.html', {'form': form}, status=200)
    elif request.method == 'POST':
        form = UserCreationForm(request.POST)
        if not form.is_valid():
            return render(request, 'file/signup.html', {'form': form}, status=200)
        form.save()
        user = User.objects.get(username=form.cleaned_data.get('username'))
        login(request, user)
        return HttpResponseRedirect("/login")
    else:
        return HttpResponse("Unsupported method Please use GET or POST ", status=405)


def log_out(request):
    if request.method == 'GET':
        token = Token.objects.get(user=request.user.id)
        token.delete()
        logout(request)
        return HttpResponseRedirect("/login")
    else:
        return HttpResponse("Unsupported method Please use GET or POST ", status=405)


def open_file(request, username, filename):
    user = User.objects.get(username=username)
    if request.user.is_authenticated and user.username == request.user.username:
        if request.method == 'GET':
            file = File.objects.get(name=filename, user = user)
            filepath = file.path
            return serve(request, os.path.basename(filepath), os.path.dirname(filepath))
    else:
        return HttpResponse("NOT FOUND", status=404)


class UserList(generics.ListCreateAPIView):
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        if self.request.user.is_superuser:
            return User.objects.all().order_by('id')
        else:
            return User.objects.filter(id=self.request.user.id).order_by('id')


class UserDetail(generics.DestroyAPIView):
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)
    lookup_url_kwarg = 'username'

    def destroy(self, request, username):
        user = User.objects.get(username=username)
        if request.user.is_superuser or user.username == request.user.username:
            token = Token.objects.filter(user = user)
            token.delete()
            user.delete()
            data = {username: "Deleted Successfully"}
            return JsonResponse(data,
                                safe=False,
                                json_dumps_params={'indent': 4})
        else:
            data = {username: "Unauthorized Deletion of User"}
            return JsonResponse(data,
                                safe=False,
                                status=400,
                                json_dumps_params={'indent': 4})


class FileList(generics.ListCreateAPIView):
    serializer_class = FileSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        user = self.request.user
        return File.objects.filter(user=user)

    def perform_create(self, serializer):
        user = User.objects.get(id = self.request.user.id)
        return serializer.save(user=user)


class FileDetail(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = FileSerializer
    permission_classes = (IsAuthenticated,)
    lookup_url_kwarg = 'filename'

    def get_queryset(self):
        return File.objects.filter(user=self.request.user)
