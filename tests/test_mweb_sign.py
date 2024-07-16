from ecdsa import SigningKey, SECP256k1
from random import randbytes
from struct import pack
import subprocess

def run_go(op, data):
    args = ["./tests/test_mweb", str(op), data.hex()]
    result = subprocess.run(args, capture_output=True)
    return bytes.fromhex(result.stdout.decode())

def test_mweb_sign(backend, firmware):
    for _ in range(1):
        data = pack('>BIII', 3, 1000 | 1<<31, 2 | 1<<31, 0 | 1<<31)
        backend.exchange(0xeb, 0x05, 0x00, 0x00, data)
        keys = randbytes(64)
        backend.exchange(0xeb, 0x99, 0x00, 0x00, keys)
        coin = randbytes(32) + pack('<Q', int(5e8)) + randbytes(72)
        input = backend.exchange(0xeb, 0x07, 0x00, 0x00, coin).data
        A = SigningKey.generate(curve=SECP256k1).verifying_key.to_string('uncompressed')
        B = SigningKey.generate(curve=SECP256k1).verifying_key.to_string('uncompressed')
        recipient = pack('<Q', int(4e8)) + A + B
        output = backend.exchange(0xeb, 0x08, 0x00, 0x00, recipient).data
        output_sig = backend.exchange(0xeb, 0x09, 0x00, 0x00, randbytes(32)).data
        kernel_args = pack('<QQII', int(1e8), int(1e8), 1, 0)
        backend.exchange(0xeb, 0x0a, 0x01, 0x00, kernel_args)
        kernel_pegout = pack('<Q', int(1e8)) + randbytes(40)
        kernel = backend.exchange(0xeb, 0x0a, 0x00, 0x00, kernel_pegout).data
        resp_go = run_go(12, keys + coin + recipient + kernel_args + kernel_pegout)
        assert resp_go == input + output + output_sig + kernel
