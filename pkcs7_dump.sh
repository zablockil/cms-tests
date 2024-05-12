#!/bin/bash

for f in ./*.p7c; do
openssl pkcs7 -inform DER -print_certs -text -in "${f}" | awk '{ sub(/[ \t]+$/, ""); print }' > "${f}.pkcs7.txt"
done
echo "done"
