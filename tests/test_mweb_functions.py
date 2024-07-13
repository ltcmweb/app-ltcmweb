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
