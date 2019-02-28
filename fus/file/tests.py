from django.test import TestCase, Client
from file.models import File
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token


class LoginTest(TestCase):
    def setUp(self):
        users = [
            {
                "username": "Karthik",
                "password": "hello123",
                "email": "a@a.com"
            },
            {
                "username": "hello",
                "password": "hello@123",
                "email": "a@a.com"
            },
        ]
        for user in users:
            User.objects.create_user(user['username'],
                                     user['password'],
                                     user['email'])
        User.objects.create_superuser(username="paapa",
                                      password="paapa123",
                                      email="a@a.com")

    def test_login_get(self):
        client = Client()
        response = client.get('/login')
        self.assertEqual(response.status_code, 200)
        response = client.get('/')
        self.assertEqual(response.status_code, 302)

    def test_login_post(self):
        client = Client()
        response = client.post('/login', {'username': 'paapa',
                                          'password': 'paapa123'})
        self.assertEqual(response.status_code, 302)
        response = client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_login_afterlogin(self):
        client = Client()
        response = client.post('/login', {'username': 'paapa',
                                          'password': 'paapa123'})
        self.assertEqual(response.status_code, 302)
        response = client.get('/login')
        self.assertEqual(response.status_code, 302)

    def test_login_invaliduser(self):
        client = Client()
        response = client.post('/login', {'username': 'kcbqecjbq',
                                          'password': 'kdcwicjbw'})
        self.assertEqual(response.status_code, 200)
        response = client.get('/')
        self.assertEqual(response.status_code, 302)

    def test_login_invalidmethod(self):
        client = Client()
        response = client.delete('/login', {'username': 'kcbqecjbq',
                                            'password': 'kdcwicjbw'})
        self.assertEqual(response.status_code, 405)


class HomeTest(TestCase):
    def setUp(self):
        users = [
            {
                "username": "Karthik",
                "password": "hello123",
                "email": "a@a.com"
            },
            {
                "username": "hello",
                "password": "hello@123",
                "email": "a@a.com"
            },
        ]
        for user in users:
            u = User.objects.create_superuser(user['username'],
                                              user['password'],
                                              user['email'])
            File.objects.create(user=u, path="/upload",
                                name="{}.jpg".format(u.username))
            File.objects.create(user=u, path="/upload",
                                name="{}.txt".format(u.username))
        User.objects.create_superuser(username="paapa",
                                      password="paapa123",
                                      email="a@a.com")
        u = User.objects.create_superuser(username="hello123",
                                          password="testcase",
                                          email="a@a.com")
        File.objects.create(user=u, path="/upload",
                            name="{}.txt".format(u.username))

    def test_home_get(self):
        client = Client()
        response = client.post('/login', {'username': 'paapa',
                                          'password': 'paapa123'})
        self.assertEqual(response.status_code, 302)
        response = client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_home_invaliduser(self):
        client = Client()
        response = client.get('/')
        self.assertEqual(response.status_code, 302)

    def test_home_withoutfiles(self):
        client = Client()
        response = client.post('/login', {'username': 'paapa',
                                          'password': 'paapa123'})
        self.assertEqual(response.status_code, 302)
        response = client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_home_withfiles(self):
        client = Client()
        response = client.post('/login', {'username': 'hello123',
                                          'password': 'testcase'})
        self.assertEqual(response.status_code, 302)
        response = client.get('/')
        self.assertEqual(response.status_code, 200)


class OpenFileTest(TestCase):
    def setUp(self):
        users = [
            {
                "username": "Karthik",
                "password": "hello123",
                "email": "a@a.com"
            },
            {
                "username": "hello",
                "password": "hello@123",
                "email": "a@a.com"
            },
        ]
        for user in users:
            u = User.objects.create_superuser(user['username'],
                                              user['password'],
                                              user['email'])
        User.objects.create_superuser(username="paapa",
                                      password="paapa123",
                                      email="a@a.com")
        u = User.objects.create_superuser(username="hello123",
                                          password="testcase",
                                          email="a@a.com")
        File.objects.create(user=u, path="/upload",
                            name="{}.txt".format(u.username))
        File.objects.create(user=u, path="/upload",
                            name="{}.jpg".format(u.username))

    def test_file_authorized_get(self):
        client = Client()
        file = File.objects.last()
        username = file.user.username
        response = client.post('/login', {'username': 'hello123',
                                          'password': 'testcase'})
        self.assertEqual(response.status_code, 302)
        response = client.get('/file/{}/{}'.format(username, file.name))
        self.assertEqual(response.status_code, 404)

    def test_file_unauthorized_get(self):
        client = Client()
        file = File.objects.last()
        username = file.user.username
        response = client.get('/file/{}/{}'.format(username, file.name))
        self.assertEqual(response.status_code, 404)


class LogoutTest(TestCase):
    def setUp(self):
        users = [
            {
                "username": "Karthik",
                "password": "hello123",
                "email": "a@a.com"
            },
            {
                "username": "hello",
                "password": "hello@123",
                "email": "a@a.com"
            },
        ]
        for user in users:
            User.objects.create_user(user['username'],
                                     user['password'],
                                     user['email'])
        User.objects.create_superuser(username="paapa",
                                      password="paapa123",
                                      email="a@a.com")

    def test_logout_get(self):
        client = Client()
        response = client.post('/login', {'username': 'paapa',
                                          'password': 'paapa123'})
        self.assertEqual(response.status_code, 302)
        response = client.get('/')
        self.assertEqual(response.status_code, 200)
        response = client.get('/logout')
        self.assertEqual(response.status_code, 302)

    def test_logout_invalidmethod(self):
        client = Client()
        response = client.post('/login', {'username': 'paapa',
                                          'password': 'paapa123'})
        self.assertEqual(response.status_code, 302)
        response = client.post('/logout')
        self.assertEqual(response.status_code, 405)


class UploadTest(TestCase):
    def setUp(self):
        users = [
            {
                "username": "Karthik",
                "password": "hello123",
                "email": "a@a.com"
            },
            {
                "username": "hello",
                "password": "hello@123",
                "email": "a@a.com"
            },
        ]
        for user in users:
            User.objects.create_user(user['username'],
                                     user['password'],
                                     user['email'])
        User.objects.create_superuser(username="paapa",
                                      password="paapa123",
                                      email="a@a.com")

    def test_upload_get(self):
        client = Client()
        response = client.post('/login', {'username': 'paapa',
                                          'password': 'paapa123'})
        self.assertEqual(response.status_code, 302)
        response = client.get('/upload')
        self.assertEqual(response.status_code, 200)

    def test_upload_invaliduser(self):
        client = Client()
        response = client.delete('/upload')
        self.assertEqual(response.status_code, 302)

    def test_upload_post(self):
        client = Client()
        response = client.post('/login', {'username': 'paapa',
                                          'password': 'paapa123'})
        self.assertEqual(response.status_code, 302)
        f = SimpleUploadedFile("urls.txt", b"file_content")
        FILES = {'file': f}
        response = client.post('/upload', FILES)

    def test_upload_invalidmethod(self):
        client = Client()
        response = client.post('/login', {'username': 'paapa',
                                          'password': 'paapa123'})
        self.assertEqual(response.status_code, 302)
        response = client.delete('/upload')
        self.assertEqual(response.status_code, 405)


class SignupTest(TestCase):
    def setUp(self):
        users = [
            {
                "username": "Karthik",
                "password": "hello123232asfdasfdas",
                "email": "a@a.com"
            },
            {
                "username": "hello",
                "password": "hello@123asdfasdf3wr5asdfsadf",
                "email": "ab@a.com"
            },
        ]
        for user in users:
            u = User.objects.create_user(user['username'],
                                         user['password'],
                                         user['email'])
            File.objects.create(user=u, path="/upload",
                                name="{}.jpg".format(u.username))
            File.objects.create(user=u, path="/upload",
                                name="{}.txt".format(u.username))

    def test_signup_get(self):
        client = Client()
        response = client.get('/signup')
        self.assertEqual(response.status_code, 200)

    def test_signup_post_invalidform(self):
        client = Client()
        response = client.post('/signup', {'username': 'paapa',
                                           'password1': 'paapa123',
                                           'password2': 'paapa123'})
        self.assertEqual(response.status_code, 200)

    def test_signup_post_validform(self):
        client = Client()
        response = client.post('/signup', {'username': 'paapa',
                                           'password1': 'test@123',
                                           'password2': 'test@123'})
        self.assertEqual(response.status_code, 302)

    def test_signup_invalidmethod(self):
        client = Client()
        response = client.delete('/signup')
        self.assertEqual(response.status_code, 405)


class FileAPIAuthenticationTest(TestCase):
    def setUp(self):
        users = [
            {
                "username": "Karthik",
                "password": "hello123",
                "email": "a@a.com"
            },
            {
                "username": "hello",
                "password": "hello@123",
                "email": "a@a.com"
            },
        ]
        for user in users:
            u = User.objects.create_user(user['username'],
                                         user['password'],
                                         user['email'])
            File.objects.create(user=u, path="/upload",
                                name="{}.jpg".format(u.username))
            File.objects.create(user=u, path="/upload",
                                name="{}.txt".format(u.username))
            Token.objects.get_or_create(user=u)
        User.objects.create_superuser(username="test123",
                                      password="testtest",
                                      email="a@a.com")

    def test_authorization_file_invalid(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + '')
        response = client.get("/api/files/")
        self.assertEqual(response.status_code, 401)

    def test_authorization_file_valid(self):
        token = Token.objects.first()
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + str(token.key))
        response = client.get("/api/files/")
        self.assertEqual(response.status_code, 200)
        token = Token.objects.last()
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + str(token.key))
        response = client.get("/api/files/")
        self.assertEqual(response.status_code, 200)


class FileAPITest(TestCase):
    def setUp(self):
        users = [
            {
                "username": "Karthik",
                "password": "hello123",
                "email": "a@a.com"
            },
            {
                "username": "hello",
                "password": "hello@123",
                "email": "a@a.com"
            },
        ]
        for user in users:
            u = User.objects.create_user(user['username'],
                                         user['password'],
                                         user['email'])
            File.objects.create(user=u, path="/upload",
                                name="{}.jpg".format(u.username))
            File.objects.create(user=u, path="/upload",
                                name="{}.txt".format(u.username))
            Token.objects.get_or_create(user=u)
        User.objects.create_superuser(username="test123",
                                      password="testtest",
                                      email="a@a.com")

    def test_file_post(self):
        token = Token.objects.first()
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + str(token.key))
        response = client.post("/api/files/", {"name": "test123.txt",
                                               "user": 1,
                                               "path": "/api/test/files", })
        self.assertEqual(response.status_code, 201)

    def test_file_delete(self):
        token = Token.objects.first()
        username = token.user.username
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + str(token.key))
        response = client.delete("/api/files/{}.txt/".format(username))
        self.assertEqual(response.status_code, 204)


class UserAPIAuthenticationTest(TestCase):
    def setUp(self):
        users = [
            {
                "username": "Karthik",
                "password": "hello123",
                "email": "a@a.com",
                "is_superuser": True
            },
            {
                "username": "hello",
                "password": "hello@123",
                "email": "a@a.com"
            },
        ]
        for user in users:
            u = User.objects.create_user(user['username'],
                                         user['password'],
                                         user['email'])
            File.objects.create(user=u, path="/upload",
                                name="{}.jpg".format(u.username))
            File.objects.create(user=u, path="/upload",
                                name="{}.txt".format(u.username))
            Token.objects.get_or_create(user=u)
        u = User.objects.create_superuser(username="test123",
                                          password="testtest",
                                          email="a@a.com")
        Token.objects.get_or_create(user=u)

    def test_authorization_user_invalid(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + '')
        response = client.get("/api/files/")
        self.assertEqual(response.status_code, 401)

    def test_authorization_list_all_user_valid(self):
        token = Token.objects.get(user=3)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + str(token.key))
        response = client.get("/api/users/")
        self.assertEqual(response.status_code, 200)

    def test_authorization_list_one_user_valid(self):
        token = Token.objects.get(user=2)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + str(token.key))
        response = client.get("/api/users/")
        self.assertEqual(response.status_code, 200)


class UserAPITest(TestCase):
    def setUp(self):
        users = [
            {
                "username": "Karthik",
                "password": "hello123",
                "email": "a@a.com"
            },
            {
                "username": "hello",
                "password": "hello@123",
                "email": "a@a.com"
            },
        ]
        for user in users:
            u = User.objects.create_user(user['username'],
                                         user['password'],
                                         user['email'])
            File.objects.create(user=u, path="/upload",
                                name="{}.jpg".format(u.username))
            File.objects.create(user=u, path="/upload",
                                name="{}.txt".format(u.username))
            Token.objects.get_or_create(user=u)
        u = User.objects.create_superuser(username="test123",
                                          password="testtest",
                                          email="a@a.com")
        Token.objects.get_or_create(user=u)


    def test_valid_user_post(self):
        token = Token.objects.get(user=3)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + str(token.key))
        json_data = {"username": "paapa123",
                     "password": "karthik123",
                     "first_name": "paapa",
                     "last_name": "Karthik",
                     "email": "a@a.com",
                     "is_superuser": "True",
                     "is_staff": "True",
                     "is_active": "True"}
        response = client.post("/api/users/", json_data, format='json')
        self.assertEqual(response.status_code, 201)

    def test_invalid_user_post(self):
        token = Token.objects.get(user=3)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + str(token.key))
        json_data = {"username": "test123",
                     "password": "karthik123",
                     "first_name": "paapa",
                     "last_name": "Karthik",
                     "email": "a@a.com",
                     "is_superuser": "True",
                     "is_staff": "True",
                     "is_active": "True"}
        response = client.post("/api/users/", json_data, format='json')
        self.assertEqual(response.status_code, 400)

    def test_authorized_user_delete(self):
        token = Token.objects.get(user=3)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + str(token.key))
        response = client.delete("/api/users/{}/".format(token.user.username))
        self.assertEqual(response.status_code, 200)

    def test_unauthorized_user_delete(self):
        token = Token.objects.get(user=2)
        username = Token.objects.get(user=1).user.username
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + str(token.key))
        response = client.delete("/api/users/{}/".format(username))
        self.assertEqual(response.status_code, 400)
