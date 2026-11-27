#!/usr/bin/env bash
set -euo pipefail
cd "${LR6_LAB_DIR:-$(dirname "$0")/..}"
umask 077
mkdir -p certs
if [[ -e certs/ca.key || -e certs/server.key ]]; then
  echo 'Certificate keys already exist. Refusing to overwrite.' >&2
  exit 1
fi
openssl req -x509 -newkey rsa:3072 -noenc -keyout certs/ca.key -out certs/ca.crt -days 365 -sha256 -subj '/CN=LR6 Local Lab CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' > /dev/null 2>&1
openssl req -newkey rsa:3072 -noenc -keyout certs/server.key -out certs/server.csr -subj '/CN=localhost' > /dev/null 2>&1
cat > certs/server.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EXT
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 365 -sha256 -extfile certs/server.ext > /dev/null 2>&1
chmod 600 certs/*.key
printf 'Local CA generated: certs/ca.crt\nServer certificate: certs/server.crt\n'
openssl x509 -in certs/server.crt -noout -subject -issuer -dates -ext subjectAltName
