openssl genrsa -out D:\avbuster\src\download\server.key 2048
openssl req -new -x509 -days 1826 -key D:\avbuster\src\download\server.key -out D:\avbuster\src\download\server.crt


openssl.exe x509 -fingerprint -sha256 -noout -in server.crt

"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" genrsa -out pvt.key 4096
"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" rsa -in pvt.key -pubout > pub.pem