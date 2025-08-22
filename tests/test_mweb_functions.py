from ecdsa import SigningKey, SECP256k1
from random import randbytes
from misc import run_go

iterations = 100

def run_test(backend, op, iter, data):
    data, result = run_go(op, iter, data)
    rapdu = backend.exchange(0xeb, 0x99, op, 0x00, data)
    assert result == rapdu.data

def test_mweb_calculate_output_key(backend):
    for i in range(iterations):
        run_test(backend, 1, i, randbytes(64))

def test_mweb_input_create(backend):
    for i in range(iterations):
        run_test(backend, 2, i, randbytes(136))

def test_mweb_sign(backend):
    for i in range(iterations):
        run_test(backend, 3, i, randbytes(64))

def test_mweb_sk_pub(backend):
    for i in range(iterations):
        run_test(backend, 4, i, randbytes(32))

def test_mweb_keychain_spend_key(backend):
    for i in range(iterations):
        run_test(backend, 5, i, randbytes(68))

def test_mweb_keychain_address(backend):
    for i in range(iterations):
        run_test(backend, 6, i, randbytes(68))

def test_mweb_sign_kernel(backend):
    for i in range(iterations):
        run_test(backend, 7, i, randbytes(64))

def test_mweb_new_commit(backend):
    for i in range(iterations):
        run_test(backend, 8, i, randbytes(40))

def test_mweb_new_blind_switch(backend):
    for i in range(iterations):
        run_test(backend, 9, i, randbytes(40))

def test_mweb_output_create(backend):
    for i in range(iterations):
        A = SigningKey.generate(curve=SECP256k1).verifying_key.to_string('uncompressed')
        B = SigningKey.generate(curve=SECP256k1).verifying_key.to_string('uncompressed')
        data = randbytes(8) + A + B + randbytes(32)
        data, result = run_go(10, i, data)
        range_proof_hash = result[-96:-64]
        resp = backend.exchange(0xeb, 0x99, 10, 0x00, data).data
        resp += range_proof_hash
        resp += backend.exchange(0xeb, 0x99, 11, 0x00, range_proof_hash).data
        assert result == resp
