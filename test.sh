
for i in {1..200}
do
./rsaengine -genrsa -pubout public_key.der -privout priv_key.der
./rsaengine -encrypt -pubin public_key.der -in message -out encrypted_message
./rsaengine -decrypt -privin priv_key.der -in encrypted_message -out decrypted_msg
./rsaengine -sign -privin priv_key.der -in message -out signature_file -certout public_certificate.der
./rsaengine -verify -signature signature_file -certin public_certificate.der -in message 
done
