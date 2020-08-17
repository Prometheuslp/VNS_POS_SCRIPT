#coding=utf-8
#! /usr/bin/python3
import time
import sys
import json

 
###########################################################################################
with open("vns_pos_index.conf", encoding="utf-8") as f:
    index_conf = json.load(f)

###########################################################################################

if __name__ == "__main__":
    index_conf["wallet_address"] = str(sys.argv[1]).strip()
    index_conf["wallet_private_key"] = str(sys.argv[2]).strip()
    index_conf["receiving_address"] = str(sys.argv[3]).strip()
    index_conf["registered_url"] = str(sys.argv[4]).strip()
    if(len(sys.argv) == 5):
        print("wallet_address: {}".format(sys.argv[1]))
        print("wallet_private_key: {}".format(sys.argv[2]))
        print("receiving_address: {}".format(sys.argv[3]))
        print("registered_url: {}".format(sys.argv[4]))
    with open("my_vns_pos_index.conf","w") as f:
        json.dump(index_conf,f)
        print("Loading the file is complete...")
