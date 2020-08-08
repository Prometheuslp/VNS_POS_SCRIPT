from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Sequence,
    Tuple,
)

from eth_typing import (
    TypeStr,
)
from eth_utils import (
    to_dict,
)
from eth_utils.curried import (
    apply_formatter_at_index,
)
from eth_utils.toolz import (
    curry,
)

from web3._utils.abi import (
    map_abi_data,
)
from web3.types import (
    RPCEndpoint,
)


class RPC:
    # admin
    admin_addPeer = RPCEndpoint("admin_addPeer")
    admin_datadir = RPCEndpoint("admin_datadir")
    admin_nodeInfo = RPCEndpoint("admin_nodeInfo")
    admin_peers = RPCEndpoint("admin_peers")
    admin_startRPC = RPCEndpoint("admin_startRPC")
    admin_startWS = RPCEndpoint("admin_startWS")
    admin_stopRPC = RPCEndpoint("admin_stopRPC")
    admin_stopWS = RPCEndpoint("admin_stopWS")

    # eth
    eth_accounts = RPCEndpoint("vns_accounts")
    eth_blockNumber = RPCEndpoint("vns_blockNumber")
    eth_call = RPCEndpoint("vns_call")
    eth_chainId = RPCEndpoint("vns_chainId")
    eth_coinbase = RPCEndpoint("vns_coinbase")
    eth_estimateGas = RPCEndpoint("vns_estimateGas")
    eth_gasPrice = RPCEndpoint("vns_gasPrice")
    eth_getBalance = RPCEndpoint("vns_getBalance")
    eth_getBlockByHash = RPCEndpoint("vns_getBlockByHash")
    eth_getBlockByNumber = RPCEndpoint("vns_getBlockByNumber")
    eth_getBlockTransactionCountByHash = RPCEndpoint("vns_getBlockTransactionCountByHash")
    eth_getBlockTransactionCountByNumber = RPCEndpoint("vns_getBlockTransactionCountByNumber")
    eth_getCode = RPCEndpoint("vns_getCode")
    eth_getFilterChanges = RPCEndpoint("vns_getFilterChanges")
    eth_getFilterLogs = RPCEndpoint("vns_getFilterLogs")
    eth_getLogs = RPCEndpoint("vns_getLogs")
    eth_getProof = RPCEndpoint("vns_getProof")
    eth_getStorageAt = RPCEndpoint("vns_getStorageAt")
    eth_getTransactionByBlockHashAndIndex = RPCEndpoint("vns_getTransactionByBlockHashAndIndex")
    eth_getTransactionByBlockNumberAndIndex = RPCEndpoint("vns_getTransactionByBlockNumberAndIndex")
    eth_getTransactionByHash = RPCEndpoint("vns_getTransactionByHash")
    eth_getTransactionCount = RPCEndpoint("vns_getTransactionCount")
    eth_getTransactionReceipt = RPCEndpoint("vns_getTransactionReceipt")
    eth_getUncleByBlockHashAndIndex = RPCEndpoint("vns_getUncleByBlockHashAndIndex")
    eth_getUncleByBlockNumberAndIndex = RPCEndpoint("vns_getUncleByBlockNumberAndIndex")
    eth_getUncleCountByBlockHash = RPCEndpoint("vns_getUncleCountByBlockHash")
    eth_getUncleCountByBlockNumber = RPCEndpoint("vns_getUncleCountByBlockNumber")
    eth_getWork = RPCEndpoint("vns_getWork")
    eth_hashrate = RPCEndpoint("vns_hashrate")
    eth_mining = RPCEndpoint("vns_mining")
    eth_newBlockFilter = RPCEndpoint("vns_newBlockFilter")
    eth_newFilter = RPCEndpoint("vns_newFilter")
    eth_newPendingTransactionFilter = RPCEndpoint("vns_newPendingTransactionFilter")
    eth_protocolVersion = RPCEndpoint("vns_protocolVersion")
    eth_sendRawTransaction = RPCEndpoint("vns_sendRawTransaction")
    eth_sendTransaction = RPCEndpoint("vns_sendTransaction")
    eth_sign = RPCEndpoint("vns_sign")
    eth_signTransaction = RPCEndpoint("vns_signTransaction")
    eth_signTypedData = RPCEndpoint("vns_signTypedData")
    eth_submitHashrate = RPCEndpoint("vns_submitHashrate")
    eth_submitWork = RPCEndpoint("vns_submitWork")
    eth_syncing = RPCEndpoint("vns_syncing")
    eth_uninstallFilter = RPCEndpoint("vns_uninstallFilter")

    # evm
    evm_mine = RPCEndpoint("evm_mine")
    evm_reset = RPCEndpoint("evm_reset")
    evm_revert = RPCEndpoint("evm_revert")
    evm_snapshot = RPCEndpoint("evm_snapshot")

    # miner
    miner_makeDag = RPCEndpoint("miner_makeDag")
    miner_setExtra = RPCEndpoint("miner_setExtra")
    miner_setEtherbase = RPCEndpoint("miner_setEtherbase")
    miner_setGasPrice = RPCEndpoint("miner_setGasPrice")
    miner_start = RPCEndpoint("miner_start")
    miner_stop = RPCEndpoint("miner_stop")
    miner_startAutoDag = RPCEndpoint("miner_startAutoDag")
    miner_stopAutoDag = RPCEndpoint("miner_stopAutoDag")

    # net
    net_listening = RPCEndpoint("net_listening")
    net_peerCount = RPCEndpoint("net_peerCount")
    net_version = RPCEndpoint("net_version")

    # parity
    parity_addReservedPeer = RPCEndpoint("parity_addReservedPeer")
    parity_enode = RPCEndpoint("parity_enode")
    parity_listStorageKeys = RPCEndpoint("parity_listStorageKeys")
    parity_netPeers = RPCEndpoint("parity_netPeers")
    parity_mode = RPCEndpoint("parity_mode")
    parity_setMode = RPCEndpoint("parity_setMode")

    # personal
    personal_ecRecover = RPCEndpoint("personal_ecRecover")
    personal_importRawKey = RPCEndpoint("personal_importRawKey")
    personal_listAccounts = RPCEndpoint("personal_listAccounts")
    personal_listWallets = RPCEndpoint("personal_listWallets")
    personal_lockAccount = RPCEndpoint("personal_lockAccount")
    personal_newAccount = RPCEndpoint("personal_newAccount")
    personal_sendTransaction = RPCEndpoint("personal_sendTransaction")
    personal_sign = RPCEndpoint("personal_sign")
    personal_signTypedData = RPCEndpoint("personal_signTypedData")
    personal_unlockAccount = RPCEndpoint("personal_unlockAccount")

    # shh
    shh_addPrivateKey = RPCEndpoint("shh_addPrivateKey")
    shh_addSymKey = RPCEndpoint("shh_addSymKey")
    shh_deleteKey = RPCEndpoint("shh_deleteKey")
    shh_deleteKeyPair = RPCEndpoint("shh_deleteKeyPair")
    shh_deleteMessageFilter = RPCEndpoint("shh_deleteMessageFilter")
    shh_deleteSymKey = RPCEndpoint("shh_deleteSymKey")
    shh_generateSymKeyFromPassword = RPCEndpoint("shh_generateSymKeyFromPassword")
    shh_getFilterMessages = RPCEndpoint("shh_getFilterMessages")
    shh_getPrivateKey = RPCEndpoint("shh_getPrivateKey")
    shh_getPublicKey = RPCEndpoint("shh_getPublicKey")
    shh_getSymKey = RPCEndpoint("shh_getSymKey")
    shh_hasKeyPair = RPCEndpoint("shh_hasKeyPair")
    shh_hasSymKey = RPCEndpoint("shh_hasSymKey")
    shh_info = RPCEndpoint("shh_info")
    shh_markTrustedPeer = RPCEndpoint("shh_markTrustedPeer")
    shh_newKeyPair = RPCEndpoint("shh_newKeyPair")
    shh_newMessageFilter = RPCEndpoint("shh_newMessageFilter")
    shh_newSymKey = RPCEndpoint("shh_newSymKey")
    shh_post = RPCEndpoint("shh_post")
    shh_setMaxMessageSize = RPCEndpoint("shh_setMaxMessageSize")
    shh_setMinPoW = RPCEndpoint("shh_setMinPoW")
    shh_subscribe = RPCEndpoint("shh_subscribe")
    shh_unsubscribe = RPCEndpoint("shh_unsubscribe")
    shh_version = RPCEndpoint("shh_version")

    # testing
    testing_timeTravel = RPCEndpoint("testing_timeTravel")

    # trace
    trace_block = RPCEndpoint("trace_block")
    trace_call = RPCEndpoint("trace_call")
    trace_filter = RPCEndpoint("trace_filter")
    trace_rawTransaction = RPCEndpoint("trace_rawTransaction")
    trace_replayBlockTransactions = RPCEndpoint("trace_replayBlockTransactions")
    trace_replayTransaction = RPCEndpoint("trace_replayTransaction")
    trace_transaction = RPCEndpoint("trace_transaction")

    # txpool
    txpool_content = RPCEndpoint("txpool_content")
    txpool_inspect = RPCEndpoint("txpool_inspect")
    txpool_status = RPCEndpoint("txpool_status")

    # web3
    web3_clientVersion = RPCEndpoint("web3_clientVersion")


TRANSACTION_PARAMS_ABIS = {
    'data': 'bytes',
    'from': 'address',
    'gas': 'uint',
    'gasPrice': 'uint',
    'nonce': 'uint',
    'to': 'address',
    'value': 'uint',
}

FILTER_PARAMS_ABIS = {
    'to': 'address',
    'address': 'address[]',
}

TRACE_PARAMS_ABIS = {
    'to': 'address',
    'from': 'address',
}

RPC_ABIS = {
    # eth
    'eth_call': TRANSACTION_PARAMS_ABIS,
    'eth_estimateGas': TRANSACTION_PARAMS_ABIS,
    'eth_getBalance': ['address', None],
    'eth_getBlockByHash': ['bytes32', 'bool'],
    'eth_getBlockTransactionCountByHash': ['bytes32'],
    'eth_getCode': ['address', None],
    'eth_getLogs': FILTER_PARAMS_ABIS,
    'eth_getStorageAt': ['address', 'uint', None],
    'eth_getProof': ['address', 'uint[]', None],
    'eth_getTransactionByBlockHashAndIndex': ['bytes32', 'uint'],
    'eth_getTransactionByHash': ['bytes32'],
    'eth_getTransactionCount': ['address', None],
    'eth_getTransactionReceipt': ['bytes32'],
    'eth_getUncleCountByBlockHash': ['bytes32'],
    'eth_newFilter': FILTER_PARAMS_ABIS,
    'eth_sendRawTransaction': ['bytes'],
    'eth_sendTransaction': TRANSACTION_PARAMS_ABIS,
    'eth_signTransaction': TRANSACTION_PARAMS_ABIS,
    'eth_sign': ['address', 'bytes'],
    'eth_signTypedData': ['address', None],
    'eth_submitHashrate': ['uint', 'bytes32'],
    'eth_submitWork': ['bytes8', 'bytes32', 'bytes32'],
    # personal
    'personal_sendTransaction': TRANSACTION_PARAMS_ABIS,
    'personal_lockAccount': ['address'],
    'personal_unlockAccount': ['address', None, None],
    'personal_sign': [None, 'address', None],
    'personal_signTypedData': [None, 'address', None],
    'trace_call': TRACE_PARAMS_ABIS,
    # parity
    'parity_listStorageKeys': ['address', None, None, None],
}


@curry
def apply_abi_formatters_to_dict(
    normalizers: Sequence[Callable[[TypeStr, Any], Tuple[TypeStr, Any]]],
    abi_dict: Dict[str, Any],
    data: Dict[Any, Any]
) -> Dict[Any, Any]:
    fields = list(set(abi_dict.keys()) & set(data.keys()))
    formatted_values = map_abi_data(
        normalizers,
        [abi_dict[field] for field in fields],
        [data[field] for field in fields],
    )
    formatted_dict = dict(zip(fields, formatted_values))
    return dict(data, **formatted_dict)


@to_dict
def abi_request_formatters(
    normalizers: Sequence[Callable[[TypeStr, Any], Tuple[TypeStr, Any]]],
    abis: Dict[RPCEndpoint, Any],
) -> Iterable[Tuple[RPCEndpoint, Callable[..., Any]]]:
    for method, abi_types in abis.items():
        if isinstance(abi_types, list):
            yield method, map_abi_data(normalizers, abi_types)
        elif isinstance(abi_types, dict):
            single_dict_formatter = apply_abi_formatters_to_dict(normalizers, abi_types)
            yield method, apply_formatter_at_index(single_dict_formatter, 0)
        else:
            raise TypeError("ABI definitions must be a list or dictionary, got %r" % abi_types)
