import requests

main_url = 'http://127.0.0.1:8000'


def test_register():
    url = main_url + '/register/'
    data = {"username": "user1", "email": "user1@gmail.com", "password": "user1@123"}
    result = requests.post(url, data=data)
    assert result.status_code == 201


def test_login():
    url = main_url + '/login/'
    data = {"username": "user1", "password": "user1@123"}
    result = requests.post(url, data=data)
    assert result.status_code == 200


# def test_forgot():
#     url = main_url + '/forgot_password/'
#     data = {"email": "nikita.pawar005@gmail.com"}
#     result = requests.post(url, data=data)
#     assert result.status_code == 200
