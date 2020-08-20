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
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from threading import Thread
import socket

 
###########################################################################################
with open("../vns_pos_index.conf", encoding="utf-8") as f:
    index_conf = json.load(f)

wallet_address       = index_conf["wallet_address"].strip()
wallet_private_key   = index_conf["wallet_private_key"].strip()
receiving_address    = index_conf["receiving_address"].strip()
registered_url       = index_conf["registered_url"].strip()
INTERVAL             = int(index_conf["INTERVAL"].strip())
remote_node          = index_conf["remote_node"]
email_info           = index_conf["email"]
###########################################################################################

GAS                  = 8000000
StakeAmount          = 10 #This should be 400000 VNS
VALIDATORS_PER_NET   = 5



class VnsPos:
    def __init__(self, wallet_address, wallet_private_key, receiving_address, registered_url, GAS, StakeAmount, VALIDATORS_PER_NET, URL = "http://localhost:8585"):
        self.wallet_address = Web3.toChecksumAddress(wallet_address)
        self.wallet_private_key = wallet_private_key
        self.receiving_address = Web3.toChecksumAddress(receiving_address)
        #self.receiving_address = receiving_address
        self.registered_url = registered_url
        self.URL = URL
        self.GAS = GAS
        self.StakeAmount = StakeAmount
        self.VALIDATORS_PER_NET = VALIDATORS_PER_NET
        self.contract_address = Web3.toChecksumAddress("0xDb6887c996428E657B79988993296601d2a32054")
        self.w3 = Web3(HTTPProvider(URL))
        self.job_pool = {'claim':{}, 'prove':{}, 'prepare':{}}
        self.shit_pool = {'checkin':{}, 'feedback':{}}
        self.logyyx = Logger('tv1_vns_pos.log', logging.INFO, logging.INFO)
        with open("../vns_pos_abi.json", encoding="utf-8") as f:
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
            self.logyyx.error(code)
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
        if not data:
            return 1, "Missing encodedABI"
        signed_txn = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        try:
            txn_hash = self.w3.eth.sendRawTransaction(signed_txn.rawTransaction.hex())
        except Exception as e: 
            self.logyyx.error(e.args)
            #self.logyyx.error(traceback.format_exc())
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
                if func == "open":
                    status, txn_hash = self.send_tx(Web3.toWei(50, 'ether'), gasprice, nonce, encodedABI)
                else:
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
                    if func == "open":
                        status, txn_hash = self.send_tx(Web3.toWei(50, 'ether'), self.job_pool[func]["gasprice"], self.job_pool[func]["nonce"], encodedABI)
                    else:
                        status, txn_hash = self.send_tx(0, self.job_pool[func]["gasprice"], self.job_pool[func]["nonce"], encodedABI)
                    self.logyyx.info("{} hash: {}".format(func, txn_hash))
                    return status, txn_hash, self.job_pool[func]["count"]
            else:
                return
        else:
            nonce = self.get_nonce(self.wallet_address)
            if func == "open":
                status, txn_hash = self.send_tx(Web3.toWei(50, 'ether'), gasprice, nonce, encodedABI)
            else:
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
                code = requests.post(self.URL, data=json.dumps(proof_req), headers=headers).text
                #print(code)
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
        #point = 90 - duration/10
        point = 100 if(point > 100) else point
        point = 1 if(point < 1) else point
        self.logyyx.info("Trying to feedback with point: {}".format(point))
        encodedABI = self.contract.encodeABI(fn_name="feedback", args = [index, address, int(point)])
        #encodedABI = self.contract.encodeABI(fn_name="feedback", args = [index, address, 90])
        #print(encodedABI)
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
                            self.logyyx.error(e.args)
                            #self.feedbackFunc(i, server_address, millisecond);
                            #self.logyyx.error(traceback.format_exc())
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
        nonce = self.w3.eth.getBlock("latest")["nonce"]
        endtime = self.contract.functions.endtime().call() 
        owner = self.contract.functions.owner().call()
        if owner.upper() == wallet_address.upper():
            if (timestamp < endtime):
                nonce = HexBytes(nonce)  # owner can also send any different nonce.
                self.logyyx.info("Trying to open new period...");
                encodedABI = self.contract.encodeABI(fn_name="open")
                self.send_vns_to_contract("open",  encodedABI,  5)
            else:
                self.job_pool['open'] = {}
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

    def try_register(self):
        server_info = self.contract.functions.get_server(self.wallet_address).call()
        if (int(server_info[0]) < 1):
            self.logyyx.info("I haven't registered yet, try registering...")
            encodedABI = self.contract.encodeABI(fn_name="register", args = [self.registered_url, self.receiving_address])
            nonce = self.get_nonce(self.wallet_address)
            value = Web3.toWei(self.StakeAmount, 'ether')
            status, txn_hash = self.send_tx(value, Web3.toWei(50,'gwei'), nonce, encodedABI)
            if not status:
                self.logyyx.info(self.w3.eth.waitForTransactionReceipt(txn_hash))
                self.logyyx.info(txn_hash)
        else:
            self.logyyx.info("I have registered")


    def pos_contract(self):
        return self.contract

    def score1_call(self):
        server_info = self.contract.functions.get_server(self.wallet_address).call()
        score1 = server_info[-9]
        return score1


    def score2_call(self):
        server_info = self.contract.functions.get_server(self.wallet_address).call()
        score2 = server_info[-8]
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

class Mail:
    def __init__(self, sender, receiver, mail_pass, mail_host = "smtp.qq.com", subject = "VNS POS"):
        self.mail_host = mail_host
        self.mail_pass = mail_pass
        self.sender = sender
        self.receiver = [receiver]
        self.subject = subject
    def send(self, content):
        content = content
        message = MIMEText(content, 'plain', 'utf-8')
        message['From'] = Header(self.sender, 'utf-8')
        message['To'] =  Header(self.receiver[0], 'utf-8')
        subject = self.subject
        message['Subject'] = Header(subject, 'utf-8')
        try:
            smtpObj = smtplib.SMTP_SSL(self.mail_host, 465)
            smtpObj.login(self.sender,self.mail_pass)
            smtpObj.sendmail(self.sender, self.receiver, message.as_string())
            smtpObj.quit()
            print('Mail sent successfully')
        except smtplib.SMTPException as e:
            print('Failed to send mail')


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


def log_loop(poll_interval, logyyx, email, available, wallet_address, contract):
    #transfer_filter = contract.events.Claim.createFilter(fromBlock="0x0", argument_filters={'server':wallet_address})
    transfer_filter = contract.events.Claim.createFilter(fromBlock="0x0")
    count = 0
    while True:
        try:
            logs = transfer_filter.get_new_entries()
            count = 0 if (count > 10) else count
            if not (count % 8):
                logyyx.info("Querying reward.")
            for event in logs:
                server = event.args.server
                value = event.args.value
                value = value / 1e+18
                info = {"server":server, "value":value}
                period = contract.functions.period().call()
                logyyx.info(str(period - 1) + " : " + str(info))
                if wallet_address.upper() == server.upper():
                    logyyx.info(str(period) + " : " + str(info))
                    if int(available):
                        email.send(str(period) + " : " + str(info))
        except Exception as e: 
            logyyx.error(e.args)
            try:
                transfer_filter = contract.events.Claim.createFilter(fromBlock="0x0")
            except Exception as e: 
                pass
        count += 1
        time.sleep(poll_interval)

class TCPServer:
    def start(self,port=8888,host='0.0.0.0'):
        # create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind((host, port))
        # start listening for connections
        s.listen(5)
        print("heart beat server is Listening at", s.getsockname())
        while True:
            conn, addr = s.accept()
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            msg = "It's %s, and I'm alive!" % now
            conn.sendall(msg.encode('utf-8'))
            conn.close()
    
def heart_beat():
    server = TCPServer()
    server.start()


if __name__ == "__main__":
    if  int(remote_node["available"]):
        vns_pos = VnsPos(wallet_address, wallet_private_key, receiving_address, registered_url, GAS, StakeAmount, VALIDATORS_PER_NET, remote_node["url"])
    else:
        vns_pos = VnsPos(wallet_address, wallet_private_key, receiving_address, registered_url, GAS, StakeAmount, VALIDATORS_PER_NET)
        vns_pos.check_net()
    if(sys.argv[-1] == 'register'):
        vns_pos.try_register()
        exit(0)
    email = ''
    email_info["available"] = 0
    if  int(email_info["available"]):
        email = Mail(email_info["from"], email_info["to"], email_info["pd"], email_info["host"], "VNS POS {}".format(registered_url))
    logyyx = vns_pos.logyyx
    vns_pos.check_address()
    pre_period  = 0
    contract = vns_pos.pos_contract()
    try:
        worker = Thread(target=log_loop, args=(60, logyyx, email, email_info["available"], wallet_address,contract), daemon=True)
        worker.start()
    except Exception as e: 
        logyyx.error(e.args)
        logyyx.error(traceback.format_exc())
    time.sleep(1)
    try:
        watch = Thread(target=heart_beat, daemon=True)
        watch.start()
    except Exception as e: 
        logyyx.error(e.args)
        logyyx.error(traceback.format_exc())
    net_jobs_counter = 0
    while 1:
        try:
            current_period = vns_pos.period_call()
            current_starttime = vns_pos.starttime_call()
            current_endtime = vns_pos.endtime_call()
            current_dividend = vns_pos.dividend_call()
            current_divNumber = vns_pos.divNumber_call()
            current_score1 = vns_pos.score1_call()
            current_score2 = vns_pos.score2_call()
            if current_period > pre_period:
                vns_pos.pool_init()
                net_jobs_counter = 0
                pre_period = current_period
                logyyx.info("pos period: {}".format(current_period))
                if int(email_info["available"]):
                    send_info = "wallet_address : {} \nregistered_url :{} \n".format(wallet_address, registered_url)
                    send_info += "pos starttime : {}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_starttime))) + '\n'
                    send_info += "pos endtime : {}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_endtime))) + "\n"
                    send_info += "pos divNumber : {}".format(current_divNumber) + "\n"
                    send_info += "pos dividend : {}".format(current_dividend) + "\n"
                    send_info += "pos period : {}".format(current_period) + "\n"
                    send_info += "pos score1 : {}".format(current_score1) + "\n"
                    send_info += "pos score2 : {}".format(current_score2) + "\n"
                    email.send(send_info)
        except Exception as e: 
            net_jobs_counter = 0
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
            if int(email_info["available"]):
                email.send(str(traceback.format_exc()))
            time.sleep(60)
            continue
        time.sleep(1)
        logyyx.info("--------------------------------------")
        logyyx.info("pos starttime  : {}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_starttime))))
        logyyx.info("pos endtime    : {}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_endtime))))
        logyyx.info("pos period     : {}".format(current_period))
        logyyx.info("pos dividend   : {}".format(current_dividend))
        logyyx.info("pos divNumber  : {}".format(current_divNumber))
        time.sleep(1)
        try:
            vns_pos.claim_reward()
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
        time.sleep(1)
        try:
            vns_pos.try_open()
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
        time.sleep(1)
        try:
            if net_jobs_counter < 10: 
                vns_pos.try_netjob()
                net_jobs_counter += 1
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
        time.sleep(1)
        try:
            vns_pos.try_txjob()
        except Exception as e: 
            logyyx.error(e.args)
            logyyx.error(traceback.format_exc())
        time.sleep(20)
        #time.sleep(INTERVAL)


 
 
