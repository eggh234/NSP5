import struct
import math
import random
from frequency import *
from collections import Counter


def padding(artificial_payload, raw_payload):
    # Get frequency of raw_payload and artificial profile payload
    artificial_frequency = frequency(artificial_payload)
    raw_payload_frequency = frequency(raw_payload)

    # Initialize the max difference and the padding byte
    max_diff = 0
    padding_byte = b""

    # Loop through all the bytes in raw_payload_frequency
    for byte, raw_freq in raw_payload_frequency.items():
        # If the byte exists in the artificial_payload, calculate the difference
        if byte in artificial_frequency:
            artificial_freq = artificial_frequency[byte]
            diff = raw_freq - artificial_freq
        # If the byte doesn't exist in artificial_payload, the diff is just the value
        else:
            diff = raw_freq

        # Find the byte with the max frequency to use for padding
        if diff > max_diff:
            max_diff = diff
            padding_byte = byte

    # Ensure padding_byte is a bytes object
    padding_byte = (
        bytes([padding_byte]) if isinstance(padding_byte, int) else padding_byte
    )

    # Append padding_byte as many times as needed to match the length
    while len(raw_payload) < len(artificial_payload):
        raw_payload += padding_byte

    return raw_payload

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload.
    # Note: only consider the differences when artificial profile has higher frequency.
    # Depending upon the difference, call raw_payload.append

    # Your code here ...
