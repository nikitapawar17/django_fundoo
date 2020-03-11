import requests

main_url = 'http://127.0.0.1:8000'


# def test_signup():
#     url = main_url + '/signup/'
#     data = {"username": "user1", "email": "user1@gmail.com", "password": "user1@123"}
#     result = requests.post(url, data=data)
#     print(result)
#     assert result.status_code == 201


def test_login():
    url = main_url + '/login/'
    data = {"username": "user1", "password": "user1@123"}
    result = requests.post(url, data=data)
    assert result.status_code == 200
