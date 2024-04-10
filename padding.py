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
            diff = value - artificial_frequency[key]
        else:
            # If key is not found in artificial_frequency, we use the value from raw_payload_frequency
            diff = value

        if diff > max_diff:
            max_diff = diff
            padding_byte = key  # Save the byte to use for padding

    # If max_diff is greater than zero, it means we have found a byte to pad
    if max_diff > 0:
        # Ensure padding_byte is an integer before converting to bytes
        if isinstance(padding_byte, int):
            padding_byte = bytes([padding_byte])
        # Append the determined padding byte to the raw_payload
        raw_payload += padding_byte

    return raw_payload

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload.
    # Note: only consider the differences when artificial profile has higher frequency.
    # Depending upon the difference, call raw_payload.append

    # Your code here ...
