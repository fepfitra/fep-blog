---
title: "SSL Setup Cheatsheet"
description: "At least, it works. With Apache as a demo"
date: "2025-5-11"
---

## `etc/hosts`
```bash
127.0.0.1 fitrafep.com
```

## Generate CA
```bash
openssl req -new -x509 -keyout ca.key -out ca.crt
openssl x509 -in ca.crt -text -noout
```

## Generate Server Key
```bash
openssl genrsa -aes128 -out server-fitrafep.key 2048
openssl req -new -key server-fitrafep.key -out server-fitrafep.csr
```

## Generate Server Certificate
```bash
openssl ca -days 365 -in server-fitrafep.csr -CA ca.crt -CAkey ca.key -set_serial 1001 -out server-fitrafep.crt
```

## Generate PEM
```bash
cat server-fitrafep.csr server-fitrafep.key > server-fitrafep.pem
```

```bash
sudo mkdir /etc/ssl/fitrafep
sudo mv server-fitrafep.* /etc/ssl/fitrafep/
```

## Enable SSL
```bash
sudo sed -i \
	-e 's/^#\(Include .*httpd-ssl.conf\)/\1/' \
	-e 's/^#\(LoadModule .*mod_ssl.so\)/\1/' \
	-e 's/^#\(LoadModule .*mod_socache_shmcb.so\)/\1/' \
	/etc/httpd/conf/httpd.conf
```

## Restart Apache
```bash
sudo apachectl restart
```

## For advance usage
Go to here [here](https://roll.urown.net/ca/ca_root_setup.html)
