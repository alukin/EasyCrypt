CURVE_NAME=secp521r1
FILE_NAME=$CURVE_NAME
SIGN_HASH=sha512

echo "Generating ECC key. Plerase use password "12345678" to be compatible with tests"
echo
openssl genpkey -aes256 -algorithm ec \
    -pkeyopt ec_paramgen_curve:$CURVE_NAME \
    -pkeyopt ec_param_enc:named_curve \
    -out $FILE_NAME\_key.pem
echo    
echo "Key generated in file $FILE_NAME"
echo
echo "Generating PKCS#10 CSR"

#Generate CSR
openssl req -new -$SIGN_HASH -key $FILE_NAME\_key.pem -out $FILE_NAME\_csr.pem

echo
echo "CSR generated to file $FILE_NAME\_csr.pem"
echo
echo "Generating self-signed X.509 certificates"
#
openssl req -x509 -$SIGN_HASH -days 730 -key  $FILE_NAME\_key.pem -in $FILE_NAME\_csr.pem -out $FILE_NAME\_cert.pem