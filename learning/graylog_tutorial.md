


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