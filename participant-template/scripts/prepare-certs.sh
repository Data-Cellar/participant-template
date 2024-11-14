#!/usr/bin/env bash

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
