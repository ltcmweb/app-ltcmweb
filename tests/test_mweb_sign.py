from ecdsa import SigningKey, SECP256k1
from random import randbytes
from struct import pack, unpack
from misc import *

def test_mweb_sign(backend, firmware, navigator):
    for i in range(10):
        hd_path = pack('>BIII', 3, 1000 | 1<<31, 2 | 1<<31, 0 | 1<<31)
        backend.exchange(0xeb, 0x05, 0x00, 0x00, hd_path)
        keys = randbytes(64)

        coin = randbytes(32) + pack('<Q', int(5e8)) + randbytes(72)
        A = SigningKey.generate(curve=SECP256k1).verifying_key.to_string('uncompressed')
        B = SigningKey.generate(curve=SECP256k1).verifying_key.to_string('uncompressed')
        recipient = pack('<Q', int(4e8)) + A + B
        kernel_args = pack('<QQHI', int(1e8), int(1e8), 1, 0)
        # ltc1qku4dqstzff0m2fr5wexkx0d8n2au6an9fk2ke3
        pk_script = bytes.fromhex('0014b72ad041624a5fb52474764d633da79abbcd7665')
        kernel_pegout = pack('<QB', int(1e8), len(pk_script)) + pk_script

        data, resp_go = run_go(12, i, keys + coin + recipient + kernel_args + kernel_pegout)
        keys, coin, recipient = unpack('64s112s138s', data[:314])
        range_proof_hash = resp_go[-32:]
        recipient_addr = run_go(13, i, A + B)[1].decode()

        backend.exchange(0xeb, 0x99, 0x00, 0x00, keys)
        input = backend.exchange(0xeb, 0x07, 0x00, 0x00, coin).data
        with backend.exchange_async(0xeb, 0x08, 0x00, 0x00, recipient):
            if not firmware.is_nano: navigator.navigate([])
            nav_to_text(navigator, firmware, 'LTC 4')
            nav_to_text(navigator, firmware, recipient_addr[:15])
            nav_accept(navigator, firmware)
        output = backend.last_async_response.data
        output_sig = backend.exchange(0xeb, 0x09, 0x00, 0x00, range_proof_hash).data
        backend.exchange(0xeb, 0x0a, 0x01, 0x00, kernel_args)
        with backend.exchange_async(0xeb, 0x0a, 0x00, 0x00, kernel_pegout):
            nav_to_text(navigator, firmware, 'LTC 1')
            nav_to_text(navigator, firmware, 'ltc1qku4dqstzff0m2f')
            nav_accept(navigator, firmware)
            nav_to_text(navigator, firmware, 'LTC 1')
            nav_accept(navigator, firmware)
            if not firmware.is_nano: nav_confirm(navigator)
        kernel = backend.exchange(0xeb, 0x0a, 0x00, 0x00, b'0').data

        assert resp_go == input + output + output_sig + kernel + range_proof_hash
