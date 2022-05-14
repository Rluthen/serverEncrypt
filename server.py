from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import nacl.secret
import nacl.utils
import nacl.pwhash
from nacl.public import PrivateKey, Box
from nacl.signing import SigningKey

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself

        # generar llaves
        priv_key = PrivateKey.generate()
        pub_key = priv_key.public_key

        # escribir archivos de llaves
        pub_key_file = open("pub.key", "w")
        pub_key_file.write(str(pub_key))
        pub_key_file.close()
        priv_key_file = open("priv.key", "w")
        priv_key_file.write(str(priv_key))
        priv_key_file.close()

        # cifrar archivo
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        box = Box(priv_key, pub_key)
        encrypted = box.encrypt(bytes(post_data.decode('utf-8'), 'utf-8'))

        # escribir archivo cifrado
        f = open("encrypted.txt", "w")
        f.write(str(encrypted.ciphertext))
        f.close()

        # firmar archivo
        signing_key = SigningKey.generate()
        signed = signing_key.sign(encrypted.ciphertext)

        # escribir archivo firmado
        fs = open("signed.txt", "w")
        # fs.write(str(signed.decode('utf-8')))
        fs.write(str(signed))
        fs.close()
        
        verify_key = signing_key.verify_key
        verify_key_bytes = verify_key.encode()

        self._set_response()
        self.wfile.write(verify_key_bytes)

        # escribir log
        fs = open("log.log", "a")
        fs.write("POST envio un archivo para procesamiento")
        fs.close()

        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\Public Kye:\n%s\nPrivate Key:\n%s\nEncrypted Body:\n%s\nEncryption Key:\n%s\n\Signed Body:\n%s\nVerify Key:\n%s\n",
            str(self.path), str(self.headers), post_data.decode('utf-8'), pub_key, priv_key, encrypted.ciphertext, priv_key, signed, verify_key_bytes)

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()