# Web3.py

[![Documentation Status](https://readthedocs.org/projects/web3py/badge/?version=latest)](https://web3py.readthedocs.io/en/latest/?badge=latest)
[![Join the chat at https://gitter.im/ethereum/web3.py](https://badges.gitter.im/ethereum/web3.py.svg)](https://gitter.im/ethereum/web3.py?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://circleci.com/gh/ethereum/web3.py.svg?style=shield)](https://circleci.com/gh/ethereum/web3.py)

A Python library for interacting with Ethereum, inspired by [web3.js](https://github.com/ethereum/web3.js).

* Python 3.6+ support

## Quickstart

[Get started in 5 minutes](https://web3py.readthedocs.io/en/latest/quickstart.html) or
[take a tour](https://web3py.readthedocs.io/en/latest/overview.html) of the library.

## Documentation

For additional guides, examples, and APIs, see the [documentation](https://web3py.readthedocs.io/en/latest/).

## Want to help?

Want to file a bug, contribute some code, or improve documentation? Excellent! Read up on our
guidelines for [contributing](https://web3py.readthedocs.io/en/latest/contributing.html),
then check out issues that are labeled
[Good First Issue](https://github.com/ethereum/web3.py/issues?q=is%3Aissue+is%3Aopen+label%3A%22Good+First+Issue%22).

## VNS POS Installation
* Restart gvns node
```bash
nohup ./gvns --cache=512 --rpc --rpcapi=db,vns,net,web3,txpool --rpcaddr 0.0.0.0 --datadir node --syncmode=full --gcmode=archive &
```
* Python 3.6+ support
```bash
sudo apt-get -y install python3.6 build-essential wget curl  git-core python3.6-dev  libssl-dev libffi-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev python3-pip
sudo pip3 install --index-url  https://pypi.tuna.tsinghua.edu.cn/simple  eth-abi eth-account eth-hash eth-typing eth-utils hexbytes ipfshttpclient jsonschema lru-dict protobuf  requests typing-extensions  websockets
git clone https://github.com/Prometheuslp/VNS_POS_SCRIPT.git
cd VNS_POS_SCRIPT/
sudo python3.6 setup.py install
```
* Modify the vns_pos_index.conf file
```bash
cd pos
python3 vns_pos_conf.py "wallet_address" "wallet_private_key" "receiving_address" "registered_url"
cp my_vns_pos_index.conf vns_pos_index.conf
```
* Run py script
```bash
nohup python3 vns_pos_index.py &
```
