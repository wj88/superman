#!/bin/sh

# A script to create a certificate signing request.

sudo openssl genrsa -des3 -out server.key 2048
sudo openssl rsa -in server.key -out server.key.insecure
mv server.key server.key.secure
mv server.key.insecure server.key
sudo openssl req -new -key server.key -out server.csr
sudo openssl ca -in server.csr -config /etc/ssl/openssl.cnf


# To convert a crt to a pem
# openssl x509 -in mycert.crt -out mycert.pem -outform PEM

# A pem is just the tail end of the crt
