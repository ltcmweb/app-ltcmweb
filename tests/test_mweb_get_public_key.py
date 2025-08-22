from struct import pack
from misc import *

def test_mweb_confirm_address(backend, device, navigator):
    data = pack('>BIIII', 3, 1000 | 1<<31, 2 | 1<<31, 0 | 1<<31, 0)
    with backend.exchange_async(0xeb, 0x05, 0x01, 0x00, data):
        nav_to_text(navigator, device, 'ltcmweb1qq0zwpj6dl')
        nav_approve(navigator, device)
