#!/usr/bin/env python3

import struct
import math
import random
from frequency import *
from collections import Counter


def padding(artificial_payload, raw_payload):
    # Calculate the frequency of each byte in the artificial_payload
    # to compare against the raw_payload.
    artificial_frequency = frequency(artificial_payload)

    # Calculate the frequency of each byte in the raw_payload.
    raw_payload_frequency = frequency(raw_payload)

    # Initialize variables for the maximum difference found and the associated byte.
    max_diff = 0
    padding_byte = None

    # Create a list of keys from raw_payload_frequency for iteration.
    keys = list(raw_payload_frequency.keys())
    index = 0  # Start with the first index.

    # Loop over the keys using a while loop.
    while index < len(keys):
        key = keys[index]  # Get the byte (key) at the current index.
        value = raw_payload_frequency[key]  # Get the frequency of the byte.

        # Get the frequency of the byte from the artificial_frequency, default to 0.
        artificial_freq = artificial_frequency.get(key, 0)

        # If the frequency is the same as in artificial_frequency, skip this byte.
        if value == artificial_freq:
            index += 1
            continue

        # Calculate the difference in frequency for this byte.
        diff = value - artificial_freq

        # If this difference is the largest seen so far, record it and the byte.
        if diff > max_diff:
            max_diff = diff
            padding_byte = key

        index += 1  # Move to the next byte.

    # After checking all bytes, if we have found a byte with a higher frequency than in
    # artificial_frequency, append it to raw_payload as padding.
    if max_diff > 0 and padding_byte is not None:
        # Convert to bytes if padding_byte is an integer.
        if isinstance(padding_byte, int):
            padding_byte = bytes([padding_byte])
        # Append the padding byte to the raw_payload.
        raw_payload += padding_byte

    # Return the modified raw_payload with padding appended.
    return raw_payload

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload.
    # Note: only consider the differences when artificial profile has higher frequency.
    # Depending upon the difference, call raw_payload.append

    # Your code here ...
