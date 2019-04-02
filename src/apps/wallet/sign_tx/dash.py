from ustruct import unpack
from trezor import ui
from trezor.messages import ButtonRequestType
from trezor.ui.text import Text
from trezor.utils import obj_eq

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
    extra_len = _unpack_varint(data)
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


async def confirm_payload(ctx, extra):
    text = Text("Confirm payload", ui.ICON_SEND, icon_color=ui.GREEN)
    text.normal("Sign transaction with this extra payload:")
    text.bold(_to_hex(extra))
    return await confirm(ctx, text, ButtonRequestType.SignTx)


def confirm_dip2_tx_payload(data):
    return (yield UIConfirmPayload(data))
