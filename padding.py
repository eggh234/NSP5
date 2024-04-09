import struct
import math
import random
from frequency import frequency
from collections import Counter


def padding(artificial_payload, raw_payload):
    """
    Appends a byte with the maximum frequency difference to the raw_payload.
    If a byte is only in the raw_payload, use its frequency as the difference.
    Repeat padding until raw_payload matches the length of artificial_payload.
    """
    artificial_freq = frequency(artificial_payload)
    raw_freq = frequency(raw_payload)

    max_diff = -1
    padding_byte = None

    # Loop over each unique byte in both payloads
    for byte in set(artificial_freq.keys()).union(raw_freq.keys()):
        artificial_byte_freq = artificial_freq.get(byte, 0)
        raw_byte_freq = raw_freq.get(byte, 0)

        # Calculate frequency difference; favor artificial_payload's frequency
        diff = artificial_byte_freq - raw_byte_freq

        # In case the byte is not in artificial_payload
        if byte not in artificial_freq:
            diff = raw_byte_freq

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
