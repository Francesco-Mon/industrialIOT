#!/bin/bash

# Numero di certificati client da generare
NUM_CLIENTS=${1:-10} # Default a 10 se non specificato

echo "Generazione di $NUM_CLIENTS certificati client..."

for i in $(seq -f "%04g" 1 $NUM_CLIENTS)
do
  DEVICE_ID="device-$i"
  echo "  -> Generazione per $DEVICE_ID"
  
  # Crea la chiave privata del client
  openssl genrsa -out $DEVICE_ID.key 2048 &> /dev/null
  
  # Crea la richiesta di firma (CSR)
  openssl req -new -key $DEVICE_ID.key -out $DEVICE_ID.csr -subj "/CN=$DEVICE_ID" &> /dev/null
  
  # Firma il certificato con la nostra CA
  openssl x509 -req -in $DEVICE_ID.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $DEVICE_ID.crt -days 365 &> /dev/null
  
  # Rimuovi il file CSR intermedio
  rm $DEVICE_ID.csr
done

echo "Generazione completata."