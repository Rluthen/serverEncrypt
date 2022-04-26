import requests

files = {'file': open('file.txt', 'rb')}

r = requests.post('http://localhost:8080',files = files)

print(r.text)