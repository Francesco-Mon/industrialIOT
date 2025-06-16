NUM_CLIENTS=${1:-1000}

echo "Generazione di $NUM_CLIENTS certificati client..."

for i in $(seq -f "%04g" 1 $NUM_CLIENTS)
do
  DEVICE_ID="device-$i"
  echo "  -> Generazione per $DEVICE_ID"
  
  openssl genrsa -out $DEVICE_ID.key 2048 &> /dev/null
  
  openssl req -new -key $DEVICE_ID.key -out $DEVICE_ID.csr -subj "/CN=$DEVICE_ID" &> /dev/null
  
  openssl x509 -req -in $DEVICE_ID.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $DEVICE_ID.crt -days 365 &> /dev/null
  
  rm $DEVICE_ID.csr
done

echo "Generazione completata."