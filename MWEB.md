MWEB instructions
=================

`CLA` = 0xEB

| `INS` | Name           | Summary |
|-------|----------------|---------|
| 0x05 | Get Public Key | Retrieve the master scan secret and spend pubkey for a given BIP32 path. Alternatively, show the MWEB address on the device for a given BIP32 path.
| 0x07 | Add Input      | Given a rewound output, builds and returns the MWEB input spending the output and adds the input to the kernel blind and stealth offset.
| 0x08 | Add Output     | Given a recipient address and amount, builds and returns an MWEB output and adds the output to the kernel blind and stealth offset.
| 0x09 | Sign Output    | After building an output, this is used to calculate the output signature given the rangeproof hash which is calculated off-device.
| 0x0A | Sign Kernel    | This command must be called in 3 phases. The first phase sets the kernel parameters. The second supplies the pegouts if any. Finally the last phase builds and returns the signed kernel.
| 0x99 | Test           | This is usually only available in a test build. It is used for performing various operations on device for unit testing.

All integers are unsigned little-endian unless indicated.
Sizes are in bytes.

Get Public Key
--------------

| Parameter | Size |
|-----------|------|
| Length of BIP32 path (`len`) | 1
| BIP32 path elements (1..`len`) | 4 * `len` (big-endian)
| Address index (optional) | 4 (big-endian)

| Response | Size |
|----------|------|
| Scan secret | 32
| Spend pubkey | 33

This command resets the running kernel blind and stealth offset and clears all structures used for building MWEB transactions.

If `P1` is non-zero, this command will read the address index and then display the MWEB address corresponding to that index on the device screen for confirmation.

Add Input
---------

| Parameter | Size |
|-----------|------|
| Blinding factor (pre-switch commit) | 32
| Value (in litoshis) | 8
| Output ID | 32
| Address index | 4
| Shared secret | 32

| Response | Size |
|----------|------|
| Input feature bit | 1
| Output ID | 32
| Commitment | 33
| Input pubkey | 33
| Output pubkey | 33
| Signature | 64

The response matches the structure of the MWEB input on-chain.

The running kernel blind and stealth offset are updated.

Add Output
----------

| Parameter | Size |
|-----------|------|
| Value (in litoshis) | 8
| Pubkey A | 65
| Pubkey B | 65

| Response | Size |
|----------|------|
| Commitment | 33
| Sender pubkey | 33
| Receiver pubkey | 33
| Output feature bit | 1
| Key exchange pubkey | 33
| View tag | 1
| Masked value | 8
| Masked nonce | 16
| Blinding factor (pre-switch commit) | 32
| Shared secret | 32

An MWEB address consists of a pair of public keys, A and B. Normally these are serialized in compressed form but as the device firmware lacks a decompression routine, they are serialized in uncompressed form in the request.

The device will ask for confirmation from the user. The destination address and value will be shown.

The structure of the response up to the masked nonce matches the fields of the MWEB output on-chain.

The running kernel blind and stealth offset are updated.

This call must be followed up with "Sign Output" with the rangeproof hash to get the output signature.

Sign Output
-----------

| Parameter | Size |
|-----------|------|
| Rangeproof hash | 32

| Response | Size |
|----------|------|
| Signature | 64

This call calculates the output signature for the given rangeproof hash. This should be called immediately following a "Add Output" as the signature requires the results from that call.
