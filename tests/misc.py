import json
import subprocess

def run_go(op, iter, data):
    file = './tests/test_vectors.json'
    test_vectors = {}
    data_key = f'{op}:{iter}:data'
    result_key = f'{op}:{iter}:result'
    try:
        with open(file) as f:
            test_vectors = json.load(f)
            data = bytes.fromhex(test_vectors[data_key])
            result = bytes.fromhex(test_vectors[result_key])
            return data, result
    except: ()
    args = ["./tests/test_mweb", str(op), data.hex()]
    result = subprocess.run(args, capture_output=True)
    result = bytes.fromhex(result.stdout.decode())
    with open(file, 'w') as f:
        test_vectors[data_key] = data.hex()
        test_vectors[result_key] = result.hex()
        json.dump(test_vectors, f, indent=4)
    return data, result
