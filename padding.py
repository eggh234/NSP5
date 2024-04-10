#!/usr/bin/env python3

import struct
import math
import random
from frequency import *
from collections import Counter


def padding(artificial_payload, raw_payload):
    padding = b""

    # Get frequency of raw_payload and artificial profile payload
    artificial_frequency = frequency(artificial_payload)
    raw_payload_frequency = frequency(raw_payload)

    max_diff = 0
    padding_byte = b""
    # Loop through all the keys and values in the raw_payload_frequency
    # dict. For each key, find the difference in frequencies or use the value directly if not in artificial_frequency.
    # Get the max frequency difference and determine the padding_byte accordingly.
    for key, value in raw_payload_frequency.items():
        if key in artificial_frequency:
            artificial_freq = artificial_frequency[key]
            diff = value - artificial_freq
        else:
            diff = value  # Use the raw_payload_frequency value directly if the key is not in artificial_frequency

        if diff > max_diff:
            padding_byte = key
            max_diff = diff

    # Ensure padding_byte is of type bytes for consistency in appending
    if isinstance(padding_byte, str):
        padding_byte = padding_byte.encode()

    raw_payload += padding_byte  # Append the determined padding byte to the raw_payload

    return raw_payload

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload.
    # Note: only consider the differences when artificial profile has higher frequency.
    # Depending upon the difference, call raw_payload.append

    # Your code here ...
