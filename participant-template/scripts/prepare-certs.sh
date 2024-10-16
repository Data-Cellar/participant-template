#!/usr/bin/env bash

# This Bash script generates a self-signed SSL/TLS certificate and converts it into a PKCS12 format. 
# The script uses OpenSSL to create the certificate and private key files, saving them in the specified ${OUT_DIR} directory. 

set -e
set -x

: "${PARTICIPANT_CERT:?}"
: "${PARTICIPANT_KEY:?}"

: "${OUT_DIR:?}"
: "${KEY_ALIAS:?}"
: "${KEY_PASSW:?}"
: "${SUBJECT:?}"
: "${USE_LETSENCRYPT:?}"

if [ "$USE_LETSENCRYPT" = "false" ]; then
    openssl req -x509 \
        -nodes \
        -newkey rsa:4096 \
        -keyout ${OUT_DIR}/${PARTICIPANT_KEY} \
        -out ${OUT_DIR}/${PARTICIPANT_CERT} \
        -days 365 \
        -subj ${SUBJECT}
fi

openssl pkcs12 -export \
    -in ${OUT_DIR}/${PARTICIPANT_CERT} \
    -inkey ${OUT_DIR}/${PARTICIPANT_KEY} \
    -out ${OUT_DIR}/cert.pfx \
    -name ${KEY_ALIAS} \
    -passout pass:${KEY_PASSW}

openssl x509 -pubkey \
    -in ${OUT_DIR}/${PARTICIPANT_CERT} \
    --noout \
    -out ${OUT_DIR}/pubkey.pem

echo "publickey=$(cat ${OUT_DIR}/${PARTICIPANT_KEY})" > \
    ${OUT_DIR}/vault.properties.temp

sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\r\\n/g' ${OUT_DIR}/vault.properties.temp > \
    ${OUT_DIR}/vault.properties

rm ${OUT_DIR}/vault.properties.temp
