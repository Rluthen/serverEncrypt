import requests

# Enviar archivo para cifrar, firmar y obetener llaves
files = {'file': open('file.txt', 'rb')}
r = requests.post('http://localhost:8080',files = files)

# Imprimir espuesta
print(r.text)