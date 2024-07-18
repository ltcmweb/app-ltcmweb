from ecdsa import SigningKey, SECP256k1
from random import randbytes
from struct import pack
import subprocess

def run_go(op, data):
    args = ["./tests/test_mweb", str(op), data.hex()]
    result = subprocess.run(args, capture_output=True)
    return bytes.fromhex(result.stdout.decode())

def test_mweb_sign(backend, firmware):
    for _ in range(100):
        data = pack('>BIII', 3, 1000 | 1<<31, 2 | 1<<31, 0 | 1<<31)
        backend.exchange(0xeb, 0x05, 0x00, 0x00, data)
        keys = randbytes(64)
        backend.exchange(0xeb, 0x99, 0x00, 0x00, keys)

        coin = randbytes(32) + pack('<Q', int(5e8)) + randbytes(72)
        A = SigningKey.generate(curve=SECP256k1).verifying_key.to_string('uncompressed')
        B = SigningKey.generate(curve=SECP256k1).verifying_key.to_string('uncompressed')
        recipient = pack('<Q', int(4e8)) + A + B
        kernel_args = pack('<QQII', int(1e8), int(1e8), 1, 0)
        # ltc1qku4dqstzff0m2fr5wexkx0d8n2au6an9fk2ke3
        pk_script = bytes.fromhex('0014b72ad041624a5fb52474764d633da79abbcd7665')
        kernel_pegout = pack('<QB', int(1e8), len(pk_script)) + pk_script

        resp_go = run_go(12, keys + coin + recipient + kernel_args + kernel_pegout)
        range_proof_hash = resp_go[-32:]

        input = backend.exchange(0xeb, 0x07, 0x00, 0x00, coin).data
        output = backend.exchange(0xeb, 0x08, 0x00, 0x00, recipient).data
        output_sig = backend.exchange(0xeb, 0x09, 0x00, 0x00, range_proof_hash).data
        backend.exchange(0xeb, 0x0a, 0x01, 0x00, kernel_args)
        backend.exchange(0xeb, 0x0a, 0x00, 0x00, kernel_pegout)
        kernel = backend.exchange(0xeb, 0x0a, 0x00, 0x00, b'0').data

        assert resp_go == input + output + output_sig + kernel + range_proof_hash
