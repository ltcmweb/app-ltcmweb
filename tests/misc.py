import json
import subprocess
from ragger.navigator.instruction import NavInsID

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

def nav(navigator, ins):
    navigator.navigate([ins], screen_change_before_first_instruction=False)

def nav_to_text(navigator, device, text, instructions=None):
    navigator.navigate_until_text(
        NavInsID.RIGHT_CLICK if device.is_nano else NavInsID.SWIPE_CENTER_TO_LEFT,
        instructions, text, screen_change_before_first_instruction=False)

def nav_accept(navigator, device):
    if device.is_nano:
        nav_to_text(navigator, device, 'Accept', [NavInsID.BOTH_CLICK])
    else:
        nav(navigator, NavInsID.USE_CASE_REVIEW_TAP)

def nav_approve(navigator, device):
    if device.is_nano:
        nav_to_text(navigator, device, 'Approve', [NavInsID.BOTH_CLICK])
    else:
        nav(navigator, NavInsID.USE_CASE_CHOICE_CONFIRM)

def nav_confirm(navigator):
    nav(navigator, NavInsID.USE_CASE_REVIEW_CONFIRM)
