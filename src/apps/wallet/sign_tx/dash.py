from ustruct import unpack
from trezor import ui
from trezor.messages import ButtonRequestType
from trezor.ui.text import Text
from trezor.utils import obj_eq
from trezor.wire import ProcessError
from trezor.crypto.base58 import encode_check

from apps.common.confirm import (
    require_confirm,
    require_hold_to_confirm,
    confirm,
)
from apps.wallet.sign_tx import (
    helpers,
)


VAR_INT_MAX_SIZE = 8


def is_dip2_tx(tx):
    if not tx.coin_name.lower().startswith("dash"):
        return False
    version = tx.version
    dip2_type = version >> 16
    version &= 0xffff
    return (version is 3) and (dip2_type > 0)


def _dip2_tx_type(tx):
    return tx.version >> 16


def _is_testnet(tx):
    return "test" in tx.coin_name.lower()


def _varint_size(data: bytes):
    size = 1
    nit = unpack("<B", data[0:1])[0]
    if nit == 253:
        size = 2
    elif nit == 254:
        size = 4
    elif nit == 255:
        size = 8
    return size


def _unpack_varint(data: bytes):
    nit = unpack("<B", data[0:1])[0]
    if nit == 253:
        nit = unpack("<H", data[0:2])[0]
    elif nit == 254:
        nit = unpack("<I", data[0:4])[0]
    elif nit == 255:
        nit = unpack("<Q", data[0:8])[0]
    return nit


def _to_hex(data: bytes) -> str:
    return "".join('{:02x}'.format(x) for x in data)


def _inet_ntoa(data: bytes) -> str:
    # this is IPv4 mapped IPv6 address,  can get only 4 last bytes
    return ".".join('{}'.format(data[i]) for i in [12, 13, 14, 15])


def _addr_from_keyid(data: bytes, testnet: bool) -> str:
    if testnet:
        prefix = b'\x8c'
    else:
        prefix = b'\x4c'
    addr_data = prefix + data[0:20]
    return encode_check(addr_data)


def _addr_from_sh(data: bytes, testnet: bool) -> str:
    if testnet:
        prefix = b'\x13'
    else:
        prefix = b'\x10'
    addr_data = prefix + data[0:20]
    return encode_check(addr_data)


def _is_p2pkh_script(data: bytes) -> bool:
    if not len(data) == 25:
        return False
    if not data[0] == 0x76:
        return False
    if not data[1] == 0xa9:
        return False
    if not data[2] == 0x14:
        return False
    if not data[-1] == 0xac:
        return False
    if not data[-2] == 0x88:
        return False
    return True


def _is_p2sh_script(data: bytes) -> bool:
    if not len(data) == 23:
        return False
    if not data[1] == 0xa9:
        return False
    if not data[2] == 0x14:
        return False
    if not data[-1] == 0x88:
        return False
    return True


def _address_from_script(data: bytes, testnet: bool) -> str:
    if _is_p2pkh_script(data):
        return _addr_from_keyid(data[3:23], testnet)
    if _is_p2sh_script(data):
        return _addr_from_sh(data[2:22], testnet)
    raise ProcessError("Unsupported payout script type")


def _revoke_reason(idx: int) -> str:
    if idx == 0:
        return "Not Specified"
    elif idx == 1:
        return "Termination of Service"
    elif idx == 2:
        return "Compromised Keys"
    elif idx == 3:
        return "Change of Keys (Not compromised)"
    return "Unknown revoke reason ({})".format(idx)


async def request_dip2_extra_payload(tx_req):
    # if it is Dash Special Tx it has at least 4 (max varint size) bytes
    # extra data, so we can request it
    size = VAR_INT_MAX_SIZE
    ofs = 0
    data = await helpers.request_tx_extra_data(tx_req, ofs, size)
    # calc full extra data size
    extra_len = _varint_size(data) + _unpack_varint(data)
    # request remaining extra data
    ofs = VAR_INT_MAX_SIZE
    data_to_confirm = bytearray(data)
    while ofs < extra_len:
        size = min(1024, extra_len - ofs)
        data = await helpers.request_tx_extra_data(tx_req, ofs, size)
        data_to_confirm.extend(data)
        ofs += len(data)
    return data_to_confirm


class UIConfirmTxDetail:
    def __init__(self, title: str, data:str):
        self.title = title
        self.data = data

    __eq__ = obj_eq


class SpecialTx:
    def __init__(self, data: bytes, dip2_type, testnet: bool, inputs_hash: bytes):
        self.payload = data
        position = 0
        # check payload size
        varint_size = _varint_size(data)
        payload_size = _unpack_varint(data[position:position + varint_size])
        if len(data) != varint_size + payload_size:
            raise ProcessError("Invalid Dash DIP2 extra payload size")
        # get tx type
        position += varint_size
        self.type = dip2_type
        self.testnet = testnet
        self.inputs_hash = inputs_hash
        self.confirmations = []
        self._parse(data, position)

    def tx_name(self):
        if self.type == 1:
            return 'Provider Registration Transaction'
        elif self.type == 2:
            return 'Provider Update Service Transaction'
        elif self.type == 3:
            return 'Provider Update Registrar Transaction'
        elif self.type == 4:
            return 'Provider Update Revocation Transaction'
        elif self.type == 5:
            return 'Coinbase Transaction'
        elif self.type == 6:
            return 'Quorum Commitment'
        elif self.type == 8:
            return 'Register Subscription Transaction'
        elif self.type == 9:
            return 'Topup BU Credit Subscription Transaction'
        elif self.type == 10:
            return 'Reset BU Key Subscription Transaction'
        elif self.type == 11:
            return 'Close BU Account Subscription Transaction'
        raise ProcessError("Unknown Dash DIP2 transaction type")

    def _parse(self, data, position):
        if self.type == 1:
            self._parse_pro_reg_tx(data, position)
        elif self.type == 2:
            self._parse_pro_up_serv_tx(data, position)
        elif self.type == 3:
            self._parse_pro_up_reg_tx(data, position)
        elif self.type == 4:
            self._parse_pro_up_rev_tx(data, position)
        elif self.type == 5:
            self._parse_cb_tx(data, position)
        elif self.type == 6:
            self._parse_qm_tx(data, position)
        elif self.type == 8:
            self._parse_bu_reg_tx(data, position)
        elif self.type == 9:
            self._parse_bu_credit_tx(data, position)
        elif self.type == 10:
            self._parse_bu_reset_tx(data, position)
        elif self.type == 11:
            self._parse_bu_close_tx(data, position)
        else:
            raise ProcessError("Unknown Dash DIP2 transaction type")

    def _parse_pro_reg_tx(self, data, position):
        version = unpack("<H", data[position:position + 2])[0]
        if not version == 1:
            raise ProcessError("Unknown Dash Provider Register format version")
        position += 2
        mntype = unpack("<H", data[position:position + 2])[0]
        position += 2
        mode = unpack("<H", data[position:position + 2])[0]
        position += 2
        self.confirmations.extend([("Masternode type",
                                    "Type: {}, mode: {}".format(mntype, mode))])
        collateral_id = _to_hex(reversed(data[position:position + 32]))
        position += 32
        collateral_out = unpack('<I', data[position:position + 4])[0]
        position += 4
        self.confirmations.extend([("External collateral",
                                    "{}:{}".format(collateral_id, collateral_out))])
        ip = _inet_ntoa(data[position:position+16])
        position += 16
        port = unpack(">H", data[position:position+2])[0]
        position += 2
        self.confirmations.extend([("Address and port",
                                    "{}:{}".format(ip, port))])
        owner_address = _addr_from_keyid(data[position:position + 20], self.testnet)
        position += 20
        self.confirmations.extend([("Owner address", owner_address)])
        self.confirmations.extend([("Operator Public Key",
                                    _to_hex(data[position:position + 48]))])
        position += 48
        voting_address = _addr_from_keyid(data[position:position + 20], self.testnet)
        position += 20
        self.confirmations.extend([("Voting address", voting_address)])
        operator_reward = unpack("<H", data[position:position+2])[0]
        if operator_reward > 10000:
            raise ProcessError("Invalid oerator reward in ProRegTx")
        position += 2
        self.confirmations.extend([("Operator reward",
                                    "{:.2f}%".format(operator_reward / 100.0))])
        varint_size = _varint_size(data[position:position + 8])
        payout_script_size = _unpack_varint(data[position:position + varint_size])
        position += varint_size
        payout_address = _address_from_script(data[position:position + payout_script_size], self.testnet)
        position += payout_script_size
        self.confirmations.extend([("Payout address", payout_address)])
        if bytes(reversed(data[position:position + 32])) != self.inputs_hash:
            raise ProcessError("Invalid inputs hash in DIP2 transaction")
        position += 32

    def _parse_pro_up_serv_tx(self, data, position):
        version = unpack("<H", data[position:position + 2])[0]
        if not version == 1:
            raise ProcessError("Unknown Dash Provider Update Service format version")
        position += 2
        initial_proregtx = _to_hex(reversed(data[position:position + 32]))
        position += 32
        self.confirmations.extend([("Initial ProRegTx", initial_proregtx)])
        ip = _inet_ntoa(data[position:position+16])
        position += 16
        port = unpack(">H", data[position:position+2])[0]
        position += 2
        self.confirmations.extend([("Address and port",
                                    "{}:{}".format(ip, port))])
        varint_size = _varint_size(data[position:position + 8])
        payout_script_size = _unpack_varint(data[position:position + varint_size])
        position += varint_size
        if payout_script_size == 0:
            payout_address = "Empty"
        else:
            payout_address = _address_from_script(data[position:position + payout_script_size], self.testnet)
        position += payout_script_size
        self.confirmations.extend([("Payout address", payout_address)])
        if bytes(reversed(data[position:position + 32])) != self.inputs_hash:
            raise ProcessError("Invalid inputs hash in DIP2 transaction")
        position += 32

    def _parse_pro_up_reg_tx(self, data, position):
        version = unpack("<H", data[position:position + 2])[0]
        if not version == 1:
            raise ProcessError("Unknown Dash Provider Update Registrar format version")
        position += 2
        initial_proregtx = _to_hex(reversed(data[position:position + 32]))
        position += 32
        self.confirmations.extend([("Initial ProRegTx", initial_proregtx)])
        mode = unpack("<H", data[position:position + 2])[0]
        position += 2
        self.confirmations.extend([("Masternode mode",
                                    "Mode: {}".format(mode))])
        self.confirmations.extend([("Operator Public Key",
                                    _to_hex(data[position:position + 48]))])
        position += 48
        voting_address = _addr_from_keyid(data[position:position + 20], self.testnet)
        position += 20
        self.confirmations.extend([("Voting address", voting_address)])
        varint_size = _varint_size(data[position:position + 8])
        payout_script_size = _unpack_varint(data[position:position + varint_size])
        position += varint_size
        if payout_script_size == 0:
            payout_address = "Empty"
        else:
            payout_address = _address_from_script(data[position:position + payout_script_size], self.testnet)
        position += payout_script_size
        self.confirmations.extend([("Payout address", payout_address)])
        if bytes(reversed(data[position:position + 32])) != self.inputs_hash:
            raise ProcessError("Invalid inputs hash in DIP2 transaction")
        position += 32

    def _parse_pro_up_rev_tx(self, data, position):
        version = unpack("<H", data[position:position + 2])[0]
        if not version == 1:
            raise ProcessError("Unknown Dash Provider Update Registrar format version")
        position += 2
        initial_proregtx = _to_hex(reversed(data[position:position + 32]))
        position += 32
        self.confirmations.extend([("Initial ProRegTx", initial_proregtx)])
        reason = unpack("<H", data[position:position + 2])[0]
        position += 2
        self.confirmations.extend([("Revoke reason", _revoke_reason(reason))])
        if bytes(reversed(data[position:position + 32])) != self.inputs_hash:
            raise ProcessError("Invalid inputs hash in DIP2 transaction")
        position += 32

    def _parse_cb_tx(self, data, position):
        raise ProcessError("Unsupported Dash DIP3 transaction type")

    def _parse_qm_tx(self, data, position):
        raise ProcessError("Unsupported Dash DIP3 transaction type")

    def _parse_bu_reg_tx(self, data, position):
        raise ProcessError("Unsupported Dash DIP3 transaction type")

    def _parse_bu_credit_tx(self, data, position):
        raise ProcessError("Unsupported Dash DIP3 transaction type")

    def _parse_bu_reset_tx(self, data, position):
        raise ProcessError("Unsupported Dash DIP3 transaction type")

    def _parse_bu_close_tx(self, data, position):
        raise ProcessError("Unsupported Dash DIP3 transaction type")


async def confirm_tx_detail(ctx, title, data):
    text = Text(title, ui.ICON_SEND, icon_color=ui.GREEN)
    text.bold(data)
    return await require_confirm(ctx, text, ButtonRequestType.SignTx)


def confirm_dip2_tx_payload(data, tx, inputs_hash):
    dip2_type = _dip2_tx_type(tx)
    testnet = _is_testnet(tx)
    tx = SpecialTx(data, dip2_type, testnet, inputs_hash)
    yield UIConfirmTxDetail("Confirm this is", tx.tx_name())
    for c in tx.confirmations:
        yield UIConfirmTxDetail(c[0], c[1])
