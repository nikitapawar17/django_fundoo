import requests

main_url = 'http://127.0.0.1:8000'


def test_signup():
    url = main_url + '/signup/'
    data = {"username": "nilam", "email": "nilammore@gmail.com", "password": "nilam@123"}
    result = requests.post(url, data=data)
    print(result)
    assert result.status_code == 201

