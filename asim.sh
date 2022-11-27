#!/bin/bash
SAMPLE_CERT_SERIAL=$(openssl x509 -inform der -in sample_cert.cer -text | grep -A1 'Serial' | sed -n '2 p')
#getting Sample certificate serial number using openssl utility and filtring out key with grep command and only extracting line 2 using sed command 
openssl x509 -inform der -in sample_cert.cer -text | grep -A6 'CRL Distribution Points'
#showing CRL’s filename. From sample certificate using openssl utility and filtering distribution point 6 depth level 
CRL_NAME=($(openssl x509 -inform der -in sample_cert.cer -text | grep -A6 'CRL Distribution Points' | cut -d"/" -f4 | grep crl))
#getting CRL name using openssl utility and filtering distribution point 6 depth level and cutting using delimiter / and again grepping crl as extension 
declare -p CRL_NAME	
#declaring CRL_NAME as array 
CRL_HTTP=($(openssl x509 -inform der -in sample_cert.cer -text | grep -A6 'CRL Distribution Points' | grep URI | grep -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*"))
#getting CRL name using openssl utility and filtering distribution point 6 depth level of CRL grepping URL and filtering http lines only by regx 
declare -p CRL_HTTP
#declaring CRL_HTTP as array 
for val in $CRL_HTTP; do
    wget $val
done
#downloading CRL revocation list  
CRL_LIST1=($( openssl crl -inform DER -text -noout -in $CRL_NAME | grep Serial | cut -d":" -f2))  
#getting serial number from revocation list 
declare -p CRL_NAME
for val in $CRL_LIST1; do
    if [ "$ SAMPLE_CERT_SERIAL" = "$VAR2" ]; then
    echo "The given certificate is on the CRL, i.e., revoked by the CA".
#comparing results to check revocation list 
else