from random import randbytes
import subprocess

def run_go(op, data):
    args = ["./tests/test_mweb", str(op), data.hex()]
    result = subprocess.run(args, capture_output=True)
    return bytes.fromhex(result.stdout.decode())

def run_test(backend, op, data):
    rapdu = backend.exchange(0xeb, 0x99, op, 0x00, data)
    assert run_go(op, data) == rapdu.data

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
        run_test(backend, 7, randbytes(64))

def test_mweb_new_commit(backend, firmware):
    for _ in range(100):
        run_test(backend, 8, randbytes(40))

def test_mweb_switch_commit(backend, firmware):
    for _ in range(100):
        run_test(backend, 9, randbytes(40))
