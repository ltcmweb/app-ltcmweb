from random import randbytes
import subprocess

def run_test(backend, op, data):
    rapdu = backend.exchange(0xeb, 0x99, op, 0x00, data)
    result = subprocess.run(["./tests/test_mweb", str(op), data.hex()], capture_output=True)
    assert bytes.fromhex(result.stdout.decode()) == rapdu.data

def test_mweb_calculate_output_key(backend, firmware):
    for _ in range(100):
        run_test(backend, 1, randbytes(64))

def test_mweb_input_create(backend, firmware):
    for _ in range(100):
        run_test(backend, 2, randbytes(96))

def test_mweb_sign(backend, firmware):
    for _ in range(100):
        run_test(backend, 3, randbytes(64))

def test_mweb_sk_pub(backend, firmware):
    for _ in range(100):
        run_test(backend, 4, randbytes(32))

def test_mweb_keychain_spend_key(backend, firmware):
    for _ in range(100):
        run_test(backend, 5, randbytes(68))

def test_mweb_keychain_address(backend, firmware):
    for _ in range(100):
        run_test(backend, 6, randbytes(68))

def test_mweb_sign_kernel(backend, firmware):
    for _ in range(100):
        data = randbytes(64)
        data2 = data[:32] + bytes(8)
        commit = subprocess.run(["./tests/test_mweb", "8", data2.hex()], capture_output=True)
        run_test(backend, 7, data + commit.stdout)
