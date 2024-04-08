#!/usr/bin/env python3

import struct
import math
import random
from frequency import *
from collections import Counter


def padding(artificial_payload, raw_payload):
    """
    Finds the byte with the largest frequency difference favoring the artificial payload and appends it to the raw_payload.
    Called repeatedly when the raw_payload is smaller than the artificial_payload.
    Handles the edge case where a byte in the raw_payload is not present in the artificial_payload by using its own frequency.
    """
    artificial_freq = frequency(artificial_payload)
    raw_freq = frequency(raw_payload)

    max_diff = 0
    padding_byte = None
    # Find the byte with the largest positive frequency difference
    for byte in set(artificial_freq).union(raw_freq):
        diff = artificial_freq.get(byte, 0) - raw_freq.get(byte, 0)
        if byte not in artificial_freq:
            diff = raw_freq[byte]
        if diff > max_diff:
            max_diff = diff
            padding_byte = byte

    # Ensure the padding_byte is a byte object
    padding_byte = (
        padding_byte if isinstance(padding_byte, bytes) else bytes([padding_byte])
    )

    # Append the padding_byte to raw_payload if needed
    while len(raw_payload) < len(artificial_payload):
        raw_payload += padding_byte

    return raw_payload

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload.
    # Note: only consider the differences when artificial profile has higher frequency.
    # Depending upon the difference, call raw_payload.append

    # Your code here ...
