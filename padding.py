import struct
import math
import random
from frequency import frequency
from collections import Counter


def padding(artificial_payload, raw_payload):
    """
    Appends the byte with the maximum frequency difference to the raw_payload.
    If a byte is not present in the artificial_payload, its frequency in the
    raw_payload is used as the difference. The padding process continues until
    the length of raw_payload matches the length of artificial_payload.
    """
    artificial_freq = frequency(artificial_payload)
    raw_freq = frequency(raw_payload)

    max_diff = -1
    padding_byte = None

    # Consider all unique bytes from both artificial and raw payloads
    unique_bytes = set(artificial_freq.keys()).union(raw_freq.keys())

    # Find the byte with the maximum frequency difference
    for byte in unique_bytes:
        # If the byte is only in raw_payload, the diff is just its raw frequency
        diff = (
            raw_freq[byte]
            if byte not in artificial_freq
            else artificial_freq.get(byte, 0) - raw_freq.get(byte, 0)
        )

        if diff > max_diff:
            max_diff = diff
            padding_byte = byte

    # Ensure padding_byte is a bytes object
    padding_byte = (
        bytes([padding_byte]) if isinstance(padding_byte, int) else padding_byte
    )

    # Calculate how many padding bytes are needed
    padding_needed = len(artificial_payload) - len(raw_payload)
    if padding_needed > 0:
        # Append the padding_byte to raw_payload as many times as needed
        raw_payload += padding_byte * padding_needed

    return raw_payload

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload.
    # Note: only consider the differences when artificial profile has higher frequency.
    # Depending upon the difference, call raw_payload.append

    # Your code here ...
