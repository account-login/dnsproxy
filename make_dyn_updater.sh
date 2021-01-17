cd out
go build -o t1 ../dyn_dns_updater/dyn_dns_updater.go
zip -r t1.zip -v dnsproxy_client.crt dnsproxy_client.key
cat t1 t1.zip >dyn_dns_updater
zip -A dyn_dns_updater
