#!/bin/bash
EASYRSA=/usr/share/easy-rsa/easyrsa
CA_NAME="example_ssl_rcp_ca_cert"

export EASYRSA_PASSIN=pass:test
export EASYRSA_PASSOUT=pass:test

echo "Cleaning up..."
rm -rf ./ca
rm -rf ./*.pem
rm -rf ./*.key
rm -rf ./*.crt

echo "Creating CA cert..."
mkdir -p ./ca
cd ./ca
$EASYRSA init-pki
cp ../vars ./pki/
$EASYRSA --batch build-ca
cp ./pki/ca.crt  ../$CA_NAME.crt

echo "Creating server certs..."
# Secures connection between RCP-Client and RCP-Server:
$EASYRSA --batch --subject-alt-name="DNS:127.0.0.1,IP:127.0.0.1" build-server-full example_ssl_rcpc_rcps_cert nopass

# Secures connection between RCP-Module and RCP-Server (module description):
$EASYRSA --batch --subject-alt-name="DNS:127.0.0.1,IP:127.0.0.1" build-server-full example_ssl_rcpm_rcps_cert nopass

# Secures connection between RCP-Server and RCP-Module (command execution):
$EASYRSA --batch --subject-alt-name="DNS:127.0.0.1,IP:127.0.0.1" build-server-full example_ssl_rcps_rcpm_cert nopass

echo "Collecting server certs..."
cp ./pki/issued/* ../
cp ./pki/private/* ../
cd ..
rm ./ca.key

echo "Merging server certs..."
for CRT in ./*.crt; do
    CRT_NAME=`basename ${CRT%.*}`
    if [ -f $CRT_NAME.key ]; then
	cat $CRT_NAME.crt $CRT_NAME.key > $CRT_NAME.pem
	rm $CRT_NAME.key
	rm $CRT_NAME.crt
    fi
done

echo "Finalizing..."
rm -rf ./ca
