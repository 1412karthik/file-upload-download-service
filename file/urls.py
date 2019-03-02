from django.urls import path, re_path
from . import views



urlpatterns = [
    path('', views.home, name='home'),
    path('login', views.log_in, name='login'),
    path('upload', views.upload, name='upload'),
    path('signup', views.signup, name='signup'),
    path('logout', views.log_out, name='logout'),
    re_path(r'file/(?P<username>.*)/(?P<filename>.*)', views.open_file, name='open_file'),
    path('api/users/', views.UserList.as_view() ),
    path('api/files/', views.FileList.as_view() ),
    re_path(r'api/users/(?P<username>.*)/', views.UserDetail.as_view()),
    re_path(r'api/files/(?P<filename>.*)/', views.FileDetail.as_view()),
]
