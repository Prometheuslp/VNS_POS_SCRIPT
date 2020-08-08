#coding=utf-8
#! /usr/bin/python3
import time
from web3 import Web3, HTTPProvider
import sys
import json
import uuid
import threading
import decimal
import asyncio
import datetime
import collections
import traceback
import urllib.request
import requests
from hexbytes import HexBytes
import logging

 
###########################################################################################
wallet_address       = "0x"
wallet_private_key   = "0x"
receiving_address    = "0x"
registered_url       = "http://10.10.8.8:8585"
INTERVAL             = 60 * 10
###########################################################################################

GAS                  = 8000000
StakeAmount          = 400000 #This should be 400000 VNS
VALIDATORS_PER_NET   = 9



class VnsPos:
    def __init__(self, wallet_address, wallet_private_key, receiving_address, registered_url, GAS, StakeAmount, VALIDATORS_PER_NET):
        self.wallet_address = Web3.toChecksumAddress(wallet_address)
        self.wallet_private_key = wallet_private_key
        self.receiving_address = receiving_address
        self.registered_url = registered_url
        self.GAS = GAS
        self.StakeAmount = StakeAmount
        self.VALIDATORS_PER_NET = VALIDATORS_PER_NET
        self.contract_address = Web3.toChecksumAddress("0xd149ab836147a1edaf1f223c9afdca7b29ecf1fd")
        self.w3 = Web3(HTTPProvider("http://localhost:8585"))
        self.job_pool = {'claim':{}, 'prove':{}, 'prepare':{}}
        self.shit_pool = {'checkin':{}, 'feedback':{}}
        self.logyyx = Logger('vns_pos.log', logging.INFO, logging.INFO)
        with open("vns_pos_abi.json", encoding="utf-8") as f:
            self.contract_abi = json.load(f)
        self.contract = self.w3.eth.contract(address = self.contract_address, abi = self.contract_abi)


    def is_vns_valid_address(self, address):
        address = str(address)
        if(address[:2] != "0x") or (len(address) != 42):
            return False
        try:
            num = int(address, 16)
        except Exception as e: 
            self.logyyx.error(e.args)
            self.logyyx.error(traceback.format_exc())
            return False
        return True


    def check_address(self):
        #code = w3.vns.getCode(Web3.toChecksumAddress(contract_address))
        code = self.w3.eth.getCode(Web3.toChecksumAddress(self.contract_address))
        if len(code) <= 2:
            self.logyyx.error("Contract address is abnormal")
            exit(1)
        if not self.is_vns_valid_address(self.wallet_address):
            self.logyyx.error("Wallet address is abnormal")
            exit(1)
        if not self.is_vns_valid_address(self.receiving_address):
            self.logyyx.error("Receiving address is abnormal")
            exit(1)
        get_address = self.w3.eth.account.privateKeyToAccount(self.wallet_private_key).address
        if get_address.upper() != self.wallet_address.upper():
            self.logyyx.error(get_address)
            self.logyyx.error(self.wallet_address)
            self.logyyx.error("Wallet address and key do not match")
            exit(1)
        self.logyyx.info("Address detection completed")
        return 0

    def pool_init(self):
        self.job_pool = {'claim':{}, 'prove':{}, 'prepare':{}}
        self.shit_pool = {'checkin':{}, 'feedback':{}}

    def check_sync(self):
        try:
            sync = self.w3.eth.syncing
        except Exception as e:
            self.logyyx.error(e.args)
            return True,e.args
        if sync:
            return True,e.args
        else:
            return False


    def check_net(self):
        if self.check_sync():
            self.logyyx.error("node is not synchronized")
            exit(1)
        IP  = "http://" + urllib.request.urlopen(\
          "http://ip.42.pl/raw").read().decode() + ":8585"
        if IP != self.registered_url:
            self.logyyx.error(IP)
            self.logyyx.error(self.registered_url)
            self.logyyx.error("IP address and contract registration address do not match")
            exit(1)
        try:
            w = Web3(HTTPProvider(self.registered_url))
            blockNumber = w.eth.blockNumber
            gasPrice = w.eth.gasPrice
        except Exception as e:
            self.logyyx.error(e.args)
            self.logyyx.error("The URL is not available")
            exit(1)
        self.logyyx.info("The current node data has been synchronized, and the latest block height is {}".format(blockNumber))
        self.logyyx.info("Network detection completed")
        return 0

    def get_nonce(self, address):
        txpool_content = self.w3.geth.txpool.content()
        nonce = self.w3.eth.getTransactionCount(address, 'latest')
        for queue_address, transaction in txpool_content['queued'].items():
            queue_address = self.w3.toChecksumAddress(queue_address)
            if queue_address == address:
                for transaction_nonce, _ in transaction.items():
                    nonce = max(nonce, int(transaction_nonce) + 1)
                break
        for pending_address, transaction in txpool_content['pending'].items():
            pending_address = self.w3.toChecksumAddress(pending_address)
            if pending_address == address:
                for transaction_nonce, _ in transaction.items():
                    nonce = max(nonce, int(transaction_nonce) + 1)
                break
        return nonce


    def send_tx(self, value, gasprice, nonce, data):
        txn_dict = {
            'from':self.wallet_address,
            'to': self.contract_address,
            'gas': self.GAS,
            'value': value,
            'gasPrice':  min(gasprice, Web3.toWei(100,'gwei')),
            'data': data,
            'nonce': nonce,
        }
        signed_txn = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        try:
            txn_hash = self.w3.eth.sendRawTransaction(signed_txn.rawTransaction.hex())
        except Exception as e: 
            self.logyyx.error(e.args)
            self.logyyx.error(traceback.format_exc())
            return 1, e.args
        return 0, txn_hash.hex()


    def txpool_content_status(self, nonce):
        txpool_content = self.w3.geth.txpool.content()
        for pending_address, transaction in txpool_content['pending'].items():
            if pending_address.upper() == self.wallet_address.upper():
                if str(nonce) in transaction.keys():
                    return 1
        for pending_address, transaction in txpool_content['queued'].items():
            if pending_address.upper() == self.wallet_address.upper():
                if str(nonce) in transaction.keys():
                    return 1
        return 0

    def send_vns_to_contract(self, func, encodedABI, interval = 5):
        gasprice = self.w3.eth.gasPrice
        if self.job_pool[func]:
            if not self.txpool_content_status(self.job_pool[func]["nonce"]):
                nonce = self.get_nonce(self.wallet_address)
                status, txn_hash = self.send_tx(0, gasprice, nonce, encodedABI)
                if not status:
                    self.job_pool[func]["nonce"] = nonce
                    self.job_pool[func]["gasprice"] = gasprice
                    self.job_pool[func]["count"] = 0
                self.logyyx.info("{} hash: {}".format(func, txn_hash))
                return status, txn_hash, 0
            self.job_pool[func]["count"] += 1
            if not (self.job_pool[func]["count"] % interval):
                increment = int(self.job_pool[func]["gasprice"] * 0.12)
                gasprice_raw = self.job_pool[func]["gasprice"]
                self.job_pool[func]["gasprice"] += increment
                self.job_pool[func]["gasprice"] = min(self.job_pool[func]["gasprice"], Web3.toWei(100,'gwei'))
                if gasprice_raw == self.job_pool[func]["gasprice"]:
                    return
                else:
                    status, txn_hash = self.send_tx(0, self.job_pool[func]["gasprice"], self.job_pool[func]["nonce"], encodedABI)
                    self.logyyx.info("{} hash: {}".format(func, txn_hash))
                    return status, txn_hash, self.job_pool[func]["count"]
            else:
                return
        else:
            nonce = self.get_nonce(self.wallet_address)
            status, txn_hash = self.send_tx(0, gasprice, nonce, encodedABI)
            if not status:
                self.job_pool[func]["nonce"] = nonce
                self.job_pool[func]["gasprice"] = gasprice
                self.job_pool[func]["count"] = 0
            self.logyyx.info("{} hash: {}".format(func, txn_hash))
            return status, txn_hash, 0

    def send_vns_to_shit(self, func, encodedABI, address, interval = 5):
        gasprice = self.w3.eth.gasPrice
        if address in self.shit_pool[func]:
            if not self.txpool_content_status(self.shit_pool[func][address]["nonce"]):
                nonce = self.get_nonce(self.wallet_address)
                status, txn_hash = self.send_tx(0, gasprice, nonce, encodedABI)
                if not status:
                    self.shit_pool[func].setdefault(address, {})["nonce"] = nonce
                    self.shit_pool[func].setdefault(address, {})["gasprice"] = gasprice
                    self.shit_pool[func].setdefault(address, {})["count"] = 0
                self.logyyx.info("{} {} hash: {}".format(func, address, txn_hash))
                return status, txn_hash, 0
            self.shit_pool[func][address]["count"] += 1
            if not (self.shit_pool[func][address]["count"] % interval):
                increment = int(self.shit_pool[func][address]["gasprice"] * 0.12)
                gasprice_raw = self.shit_pool[func][address]["gasprice"]
                self.shit_pool[func][address]["gasprice"] += increment
                self.shit_pool[func][address]["gasprice"] = min(self.shit_pool[func][address]["gasprice"], Web3.toWei(100,'gwei'))
                if gasprice_raw == self.shit_pool[func][address]["gasprice"]:
                    return
                else:
                    status, txn_hash = self.send_tx(0, self.shit_pool[func][address]["gasprice"], self.shit_pool[func][address]["nonce"], encodedABI)
                    self.logyyx.info("{} {} hash: {}".format(func, address, txn_hash))
                    return status, txn_hash, self.shit_pool[func][address]["count"]
            else:
                return
        else:
            nonce = self.get_nonce(self.wallet_address)
            status, txn_hash = self.send_tx(0, gasprice, nonce, encodedABI)
            if not status:
                self.shit_pool[func].setdefault(address, {})["nonce"] = nonce
                self.shit_pool[func].setdefault(address, {})["gasprice"] = gasprice
                self.shit_pool[func].setdefault(address, {})["count"] = 0
            self.logyyx.info("{} {} hash: {}".format(func, address, txn_hash))
            return status, txn_hash, 0

    def claim_reward(self):
        period = self.contract.functions.period().call()
        server_info = self.contract.functions.get_server(self.wallet_address).call()
        #print(server_info)
        dividend = server_info[10]
        if (period < 2) or (dividend >= period - 1):
            self.logyyx.info("The {}th reward has been completed...".format(dividend))
            self.job_pool['claim'] = {}
            return
        encodedABI = self.contract.encodeABI(fn_name="claim")
        log =  self.send_vns_to_contract("claim", encodedABI, 5)
        return log

    def try_txjob(self):
        self.logyyx.info("Querying tx jobs.")
        period = self.contract.functions.period().call()
        txjob_size  = self.contract.functions.get_txjob_length(period).call()
        txjob = 0
        for i in range(txjob_size):
            worker = self.contract.functions.get_txjob(period, i).call()
            if (worker[0].upper() == self.wallet_address.upper()):
                txjob = 1
            if ((worker[0].upper() == self.wallet_address.upper()) and (worker[3])):
                self.logyyx.info("My tx job has been completed. ")
                self.job_pool['prove'] = {}
                return
            if ((worker[0].upper() == self.wallet_address.upper()) and (not worker[3])):
                tx_height = worker[2]
                self.logyyx.info("Found my tx job. ")
                self.logyyx.info("tx_height: {}".format(tx_height))
                headers = {'content-type': 'application/json'}
                proof_req = {"jsonrpc": "2.0","method": "vns_getAccountProof",\
                        "params": [
                                    self.wallet_address,\
                                    self.w3.toHex(worker[2])\
                                  ],
                            "id": 1\
                        }
                #code = requests.post(self.registered_url, data=json.dumps(proof_req), headers=headers).text #TODO
                code = requests.post('http://localhost:8585', data=json.dumps(proof_req), headers=headers).text
                json_code = json.loads(code)
                b = HexBytes(json_code["result"])
                encodedABI = self.contract.encodeABI(fn_name="prove", args = [i, tx_height, b])
                ####
                log =  self.send_vns_to_contract("prove", encodedABI, 3)
                #print(log)
                return log
        if not txjob:
            self.logyyx.info("Not found my tx job. ")

    def feedbackFunc(self, index, address, duration):
        point = 100 - duration/10
        point = 100 if(point > 100) else point
        point = 1 if(point < 1) else point
        self.logyyx.info("Trying to feedback with point: {}".format(point))
        encodedABI = self.contract.encodeABI(fn_name="feedback", args = [index, address, int(point)])
        log =  self.send_vns_to_shit("feedback", encodedABI, address, 5)
        return log

    def try_netjob(self):
        self.logyyx.info("Querying net jobs. ")
        period = self.contract.functions.period().call()
        netjob_size  = self.contract.functions.get_netjob_length(period).call()
        netjob = 0
        for i in range(netjob_size):
            validators = self.contract.functions.get_netjob(period, i).call()
            server_address = validators[0]
            for j in range(self.VALIDATORS_PER_NET):
                validator = validators[4][j]
                address = validator[0]
                signed = validator[1]
                point = int(validator[2])
                if ((address.upper() == self.wallet_address.upper()) and (point == 0)):
                    netjob = 1
                    server_info = self.contract.functions.get_server(server_address).call()
                    #print(server_info)
                    server_url = server_info[2]
                    #self.logyyx.info(validators)
                    if (signed):
                        start = time.time()
                        millisecond = 1000;
                        try:
                            temp_w3 = Web3(HTTPProvider(server_url))
                            sync = temp_w3.eth.syncing
                            if sync:
                                self.feedbackFunc(i, server_address, millisecond)
                            else:
                                end = time.time()
                                millisecond = end - start
                                self.feedbackFunc(i, server_address, millisecond)
                        except Exception as e: 
                            self.feedbackFunc(i, server_address, millisecond);
                            self.logyyx.error(e.args)
                            self.logyyx.error(traceback.format_exc())
                        try:
                            del self.shit_pool["checkin"][server_address]
                        except Exception as e: 
                            pass
                    else:
                        self.logyyx.info("Let's check in, try {}".format(server_address));
                        encodedABI = self.contract.encodeABI(fn_name="checkin", args = [i, server_address, self.registered_url])
                        self.send_vns_to_shit("checkin",  encodedABI, server_address, 5)
                    time.sleep(1)
                if ((address.upper() == self.wallet_address.upper()) and (point > 0)):
                    try:
                        del self.shit_pool["feedback"][server_address]
                    except Exception as e: 
                        pass
        if not netjob:
            self.logyyx.info("Not found my net job. ")
        #print(self.shit_pool['checkin'])

    def try_open(self):
        #self.logyyx.info("Trying to open new period...")#TODO
        timestamp = self.w3.eth.getBlock("latest")["timestamp"]
        endtime = self.contract.functions.endtime().call() 
        if (timestamp < endtime):
            period = self.contract.functions.period().call()
            if (period >= 1):
                txjob_size = self.contract.functions.get_txjob_length(period).call()
                div_number = self.contract.functions.divNumber().call()
                # if txjobs length is less than target size, we fullfill new job
                if (int(txjob_size) <  int(div_number/10)): 
                    # jobs is not full yet
                    self.logyyx.info("Jobs are not full, prepare one...")
                    encodedABI = self.contract.encodeABI(fn_name="prepare")
                    self.send_vns_to_contract("prepare",  encodedABI,  10)
                else:
                    self.job_pool['prepare'] = {}

    def pos_contract(self):
        return self.contract

    def score1_call(self):
        score1 = self.contract.functions.score1().call()
        return score1

    def score2_call(self):
        score2 = self.contract.functions.score2().call()
        return score2

    def starttime_call(self):
        start = self.contract.functions.starttime().call()
        return start

    def endtime_call(self):
        end = self.contract.functions.endtime().call()
        return end

    def divNumber_call(self):
        div = self.contract.functions.divNumber().call()
        return div

    def period_call(self):
        period = self.contract.functions.period().call()
        return period

    def dividend_call(self):
        server_info = self.contract.functions.get_server(self.wallet_address).call()
        dividend = server_info[10]
        return dividend

class Logger:
    def __init__(self, path, clevel=logging.INFO, Flevel=logging.INFO):
        self.logger = logging.getLogger(path)
        self.logger.setLevel(logging.INFO)
        fmt = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%Y-%m-%d %H:%M:%S')
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        sh.setLevel(clevel)
        fh = logging.FileHandler(path)
        fh.setFormatter(fmt)
        fh.setLevel(Flevel)
        self.logger.addHandler(sh)
        self.logger.addHandler(fh)
    def debug(self, message):
        self.logger.debug(message)
    def info(self, message):
        self.logger.info(message)
    def war(self, message):
        self.logger.warn(message)
    def error(self, message):
        self.logger.error(message)
    def cri(self, message):
        self.logger.critical(message)


if __name__ == "__main__":
    vns_pos = VnsPos(wallet_address, wallet_private_key, receiving_address, registered_url, GAS, StakeAmount, VALIDATORS_PER_NET)
    logyyx = vns_pos.logyyx
    vns_pos.check_net()
    vns_pos.check_address()
    pre_period  = 0
    contract = vns_pos.pos_contract()
    #transfer_filter = contract.events.Claim.createFilter(fromBlock="0x0")
    while 1:
        try:
            current_period = vns_pos.period_call()
            if current_period > pre_period:
                vns_pos.pool_init()
                pre_period = current_period
                logyyx.info("pos period: {}".format(current_period))
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
            time.sleep(120)
            continue
        time.sleep(3)
        logyyx.info("--------------------------------------".format(current_period))
        try:
            current_starttime = vns_pos.starttime_call()
            current_endtime = vns_pos.endtime_call()
            current_dividend = vns_pos.dividend_call()
            current_divNumber = vns_pos.divNumber_call()
            logyyx.info("pos starttime  : {}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_starttime))))
            logyyx.info("pos endtime    : {}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_endtime))))
            logyyx.info("pos period     : {}".format(current_period))
            logyyx.info("pos dividend   : {}".format(current_dividend))
            logyyx.info("pos divNumber  : {}".format(current_divNumber))
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
        time.sleep(2)
        try:
            vns_pos.claim_reward()
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
        time.sleep(2)
        try:
            vns_pos.try_open()
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
        time.sleep(2)
        try:
            vns_pos.try_txjob()
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
        time.sleep(2)
        try:
            vns_pos.try_netjob()
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
        time.sleep(2)
        """
        try:
            claim_info = transfer_filter.get_new_entries()
            if claim_info:
                logyyx.info(claim_info)
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
        """
        #time.sleep(10)
        time.sleep(INTERVAL)


 
 