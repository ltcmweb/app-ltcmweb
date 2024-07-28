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

Get Public Key
--------------

| Parameter | Size (bytes) | Endianess |
|-----------|--------------|-----------|
| Length of BIP32 path (`len`) | 1
| BIP32 path elements (1..`len`) | 4 * `len` | Big
| Address index (optional) | 4 | Big

| Response | Size (bytes) | Endianess |
|----------|--------------|-----------|
| Scan secret | 32
| Spend pubkey | 33

This command resets the running kernel blind and stealth offset and clears all structures used for building MWEB transactions.

If `P1` is non-zero, this command will read the address index and then display the MWEB address corresponding to that index on the device screen for confirmation.
