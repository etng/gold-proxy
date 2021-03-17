PROXY_URL=localhost:9293
run:
	echo > data/logs/proxy.log
	rm -fr data/tmp/* || echo "no files in tmp"
	go run cmd/main.go
test:
	curl -x${PROXY_URL}  https://ip.fm -v
img:
	curl -v -L  -x${PROXY_URL} https://images.livemint.com/img/2021/03/08/600x338/uber3-kijB--621x414@LiveMint_1615213477687.JPG -k -odata/tmp/image.jpg
key:
	openssl genrsa -out server.key 2048
	openssl req -new -x509 -key server.key -subj "/C=CN/ST=SiChuan/L=ChengDu/O=DataPeeker Inc/OU=ProxyPooler/CN=*"  -out server.crt -days 3650
