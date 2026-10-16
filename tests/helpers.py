import re


def token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="(\w+)"', html).group(1)


def register(client, username="admin1", password="Test@1234", email="a@example.com"):
    return client.post("/register", data=dict(
        csrf_token=token(client, "/register"), username=username, email=email, password=password))


def login(client, username, password="Test@1234", follow=False):
    return client.post("/login", data=dict(
        csrf_token=token(client, "/login"), username=username, password=password),
        follow_redirects=follow)


def logout(client):
    return client.post("/logout", data=dict(csrf_token=token(client, "/dashboard")))
