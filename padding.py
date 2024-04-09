#!/usr/bin/env python3

import struct
import math
import random
from frequency import *
from collections import Counter


def padding(artificial_payload, raw_payload):
    padding = ""

    # Get frequency of raw_payload and artificial profile payload
    artificial_frequency = frequency(artificial_payload)
    raw_payload_frequency = frequency(raw_payload)

    max = 0
    padding_byte = ""
    # Loop through all the keys and values in the raw_payload_frequency
    # dict. For each key that exists in artificial_payload ,  find the difference in
    # frequencies. Get the max frequency and append that to raw_payload
    for key, value in raw_payload_frequency.items():
        if key in artificial_frequency:
            artificial_freq = artificial_frequency[key]
            diff = value - artificial_freq
            if diff > max:
                padding_byte = key
                max = diff

    raw_payload.append(padding_byte)

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload.
    # Note: only consider the differences when artificial profile has higher frequency.
    # Depending upon the difference, call raw_payload.append

    # Your code here ...
