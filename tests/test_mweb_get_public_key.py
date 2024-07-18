from ragger.navigator.instruction import NavInsID
from struct import pack

def nav(navigator, text, click=False):
    instructions = [NavInsID.BOTH_CLICK] if click else None
    navigator.navigate_until_text(NavInsID.RIGHT_CLICK, instructions, text,
                                  screen_change_before_first_instruction=False)

def test_mweb_confirm_address(backend, firmware, navigator):
    data = pack('>BIIII', 3, 1000 | 1<<31, 2 | 1<<31, 0 | 1<<31, 0)
    with backend.exchange_async(0xeb, 0x05, 0x01, 0x00, data):
        nav(navigator, 'ltcmweb1qq0zwpj6dl')
        nav(navigator, 'Approve', True)
