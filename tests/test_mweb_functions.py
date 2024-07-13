from random import randbytes
import subprocess

def test_mweb_calculate_output_key(backend, firmware):
    for _ in range(100):
        data = randbytes(64)
        rapdu = backend.exchange(0xeb, 0x99, 0x01, 0x00, data)
        result = subprocess.run(["./tests/test_mweb", "1", data.hex()], capture_output=True)
        assert bytes.fromhex(result.stdout.decode()) == rapdu.data
