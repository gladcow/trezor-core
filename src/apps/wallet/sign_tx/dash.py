from ustruct import unpack
from trezor import ui
from trezor.messages import ButtonRequestType
from trezor.ui.text import Text
from trezor.utils import obj_eq
from trezor.wire import ProcessError

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


def _to_hex(data: bytes):
    return "".join('{:02x}'.format(x) for x in data)


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


class UIConfirmPayload:
    def __init__(self, payload: bytes):
        self.payload = payload

    __eq__ = obj_eq


class UIConfirmTxType:
    def __init__(self, txtype: str):
        self.txtype = txtype

    __eq__ = obj_eq


class SpecialTx:
    def __init__(self, data: bytes):
        self.payload = data
        position = 0
        # check payload size
        varint_size = _varint_size(data)
        payload_size = _unpack_varint(data[position:varint_size])
        if len(data) != varint_size + payload_size:
            raise ProcessError("Invalid Dash DIP2 extra payload size")
        # get tx type
        position += varint_size
        self.type = unpack("<H", data[position:position + 2])[0]

    def tx_name(self):
        print("Tx Type: ", self.type)
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


async def confirm_payload(ctx, extra):
    text = Text("Confirm payload", ui.ICON_SEND, icon_color=ui.GREEN)
    text.normal("Sign transaction with this extra payload:")
    text.bold(_to_hex(extra))
    return await confirm(ctx, text, ButtonRequestType.SignTx)


async def confirm_txtype(ctx, txtype):
    text = Text("Confirm this is ", ui.ICON_SEND, icon_color=ui.GREEN)
    text.bold(txtype)
    return await confirm(ctx, text, ButtonRequestType.SignTx)


def confirm_dip2_tx_payload(data):
    tx = SpecialTx(data)
    yield UIConfirmTxType(tx.tx_name())
    return (yield UIConfirmPayload(data))
