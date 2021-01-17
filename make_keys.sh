mkdir -p t
openssl req -x509 -newkey rsa:4096 -keyout ./t/dnsproxy_ca.key -out ./t/dnsproxy_ca.crt -subj "/C=US/CN=dnsproxy_ca" -nodes -days 10000
openssl req -new -sha256 -nodes -newkey rsa:4096 -keyout ./t/dnsproxy_client.key -subj "/C=US/CN=dnsproxy_client" -out ./t/dnsproxy_client.csr
openssl x509 -req -in ./t/dnsproxy_client.csr -CA ./t/dnsproxy_ca.crt -CAkey ./t/dnsproxy_ca.key -CAcreateserial -out ./t/dnsproxy_client.crt -days 10000 -sha256
