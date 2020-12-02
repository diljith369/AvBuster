openssl genrsa -out pvt.key 4096
openssl rsa -in pvt.key -pubout > pub.pem