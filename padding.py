#!/usr/bin/env python3

import struct
import math
import random
from frequency import *
from collections import Counter


def padding(artificial_payload, raw_payload):
    # Ensure inputs are bytearrays for binary data manipulation
    if isinstance(artificial_payload, str):
        artificial_payload = artificial_payload.encode()
    if isinstance(raw_payload, str):
        raw_payload = raw_payload.encode()

    artificial_frequency = frequency(artificial_payload)
    raw_payload_frequency = frequency(raw_payload)

    # Initialize to find a byte with the max frequency difference in favor of artificial_payload
    max_diff = -1
    padding_byte = b"\x00"  # Default padding byte
    # Loop through bytes in artificial_frequency and raw_payload_frequency
    for byte in set(artificial_frequency.keys()).union(raw_payload_frequency.keys()):
        artificial_freq = artificial_frequency.get(byte, 0)
        raw_freq = raw_payload_frequency.get(byte, 0)
        diff = raw_freq - artificial_freq if byte in artificial_frequency else raw_freq
        # Looking for a byte more common in artificial_payload than in raw_payload,
        # or only in raw_payload
        if diff > max_diff:
            max_diff = diff
            padding_byte = byte if isinstance(byte, bytes) else bytes([byte])

    # Calculate how many padding bytes are needed
    padding_needed = len(artificial_payload) - len(raw_payload)
    if padding_needed > 0:
        # Append the chosen padding_byte to the raw_payload as many times as needed
        raw_payload += padding_byte * padding_needed

    return raw_payload

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload.
    # Note: only consider the differences when artificial profile has higher frequency.
    # Depending upon the difference, call raw_payload.append

    # Your code here ...
