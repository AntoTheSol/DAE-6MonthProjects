


prerequisites

```bash

sudo apt update && sudo apt upgrade
sudo apt install apt-transport-https openjdk-17-jre-headless uuid-runtime pwgen dirmngr gnupg wget

```


Installing MongoDB 7.0 for our Debian Bookworm Distros

```bash

# Import MongoDB GPG key (modern way)
wget -qO- https://www.mongodb.org/static/pgp/server-7.0.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg

# Add MongoDB repository for Debian Bookworm
echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] http://repo.mongodb.org/apt/debian bookworm/mongodb-org/7.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

# Update and install
sudo apt-get update
sudo apt-get install -y mongodb-org

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable mongod.service
sudo systemctl start mongod.service
sudo systemctl status mongod.service

```

Adding root-ca.pem from Wazuh Indexer to enable greylog communication

```bash
# Copy the root CA certificate from Windows to your WSL Graylog certs directory
mkdir -p /etc/graylog/server/certs
sudo cp /mnt/c/Users/Jonah/Desktop/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem /etc/graylog/server/certs/rootCA.crt

# Add RootCA to Keystore
cp -a /usr/lib/jvm/java-17-openjdk-amd64/lib/security/cacerts /etc/graylog/server/certs/cacerts
keytool -importcert -keystore /etc/graylog/server/certs/cacerts -storepass changeit -alias root_ca -file /etc/graylog/server/certs/rootCA.crt
```

![Prompt when adding to Keystore](img/)

Add cacerts keystore to default Graylog Java options

```bash

nano /etc/default/graylog-server

```

Add this line

```
GRAYLOG_SERVER_JAVA_OPTS="$GRAYLOG_SERVER_JAVA_OPTS -Dlog4j2.formatMsgNoLookups=true -Djavax.net.ssl.trustStore=/etc/graylog/server/certs/cacerts -Djavax.net.ssl.trustStorePassword=changeit"
```

![/etc/default/graylog-server](img/graylog_server_java_options.png)


Edit Configuration file

```bash

nano /etc/graylog/server/server.conf

```

Create a secret password within the configuration file

```bash

pwgen -N 1 -s 96

```

Within the configuration file we also create a sha256sum password with the following command below.

```bash

echo -n "Enter Password: " && head -1 </dev/stdin | tr -d '\n' | sha256sum | cut -d" " -f1

```


![Creating Wazuh User for Graylog](img/graylog_wazuh_user.png)

When creating the user as shown in the picture above we take those credentials we just made and replaced them in the configuration file for graylog. All we need to do is replace `user` and `pass` below. 

```bash

elasticsearch_hosts = https://user:pass@wazuh-indexerhostname:9200

```


Now we start gray log

```bash

sudo systemctl daemon-reload
sudo systemctl enable graylog-server.service
sudo systemctl start graylog-server.service
sudo systemctl --type=service --state=active | grep graylog 


```


using `nano /etc/graylog/server/server.conf` might be a good idea to change the `http_bind_address` from `127.0.0.1:9000` to `0.0.0.0:9000`. This will allow any interface to connect to it.