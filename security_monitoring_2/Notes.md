sudo apt update
sudo apt install flex bison build-essential

# LibMMDB (MaxMind GeoIP database support) - Very useful for network analysis
sudo apt install libmaxminddb-dev

# LibKrb5 (Kerberos authentication analysis):
sudo apt install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev swig zlib1g-dev

# GoldLinker - Faster linking during compilation, but not essential
sudo apt install binutils-gold

# Node.js - Only needed if you want Node.js bindings for Zeek
sudo apt install nodejs npm libnode-dev

# Install ZeroMQ
sudo apt install libzmq3-dev

# C++ Bindings that Zeek uses
sudo apt install libczmq-dev

make distclean
./configure

```

- When running the ./configure command it might take anywhere from 20-30 minutes to completecd 

![Zeek Configure](img/zeek_configure1_1.png)
![Zeek Configure](img/zeek_configure1_2.png)