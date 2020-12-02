openssl genrsa -out D:\avbuster\src\download\server.key 2048
openssl req -new -x509 -days 1826 -key D:\avbuster\src\download\server.key -out D:\avbuster\src\download\server.crt
openssl x509 -fingerprint -sha256 -noout -in D:\avbuster\src\download\server.crt