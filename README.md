- Esse projeto tem as seguintes finalidades:
  - Demostrar a geração de tokens jwt no formato JWS com criptogradia assincrona usando os algoritimos RSA e ECDSA
  - - Demostrar a geração de tokens jwt no formato JWE com criptogradia assincrona usando os algoritimos RSA
  - Demostrar a geração de JWK com os algoritimos RSA e ECDSA
  - Validalação do token jwt
 
#  
# Comandos para geração de chaves usando o open ssl
- gerar chave privada RSA 2048
  - openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

- gerar chave publica RSA 2048
  - openssl rsa -pubout -in private_key.pem -out public_key.pem



- gerar chave privada ecdsa 256
  - openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem


- gerar chave publica ecdsa 256
  - openssl ec -in private-key.pem -pubout -out public-key.pem
