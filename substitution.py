#!/usr/bin/env python3

import struct
import math
import dpkt
import socket
from collections import Counter
from frequency import *


import random
from frequency import frequency


def substitute(attack_payload, substitution_table):
    """
    Substitutes each byte in the attack_payload with a byte from the substitution_table.
    It picks a byte based on the weighted frequency as given in the table.
    """
    b_attack_payload = bytearray(attack_payload)
    result = bytearray()
    xor_table = bytearray()

    for byte in b_attack_payload:
        # If the byte is in the table, we use the weighted probability to pick a substitution
        if byte in substitution_table:
            substitutions = substitution_table[byte]
            weights = [freq for _, freq in substitutions]
            chosen_byte = random.choices(
                [byte for byte, _ in substitutions], weights=weights, k=1
            )[0]
            result.append(chosen_byte)
            xor_table.append(byte ^ chosen_byte)
        else:
            # If the byte is not in the table, it's left unchanged (though this should not happen)
            result.append(byte)
            xor_table.append(0)  # XOR with 0 leaves the original byte unchanged

    return (xor_table, result)


def getSubstitutionTable(artificial_payload, attack_payload):
    """
    Generates a substitution table based on the frequency of bytes in both
    the artificial and attack payloads. The substitution is one-to-many, meaning
    each byte in the attack payload can be substituted by multiple bytes from
    the artificial payload with weights based on their frequencies.
    """
    artificial_freq = frequency(artificial_payload)
    attack_freq = frequency(attack_payload)

    # Create sorted lists from most to least frequent
    sorted_artificial_freq = sorted(
        artificial_freq.items(), key=lambda item: item[1], reverse=True
    )
    sorted_attack_freq = sorted(
        attack_freq.items(), key=lambda item: item[1], reverse=True
    )

    substitution_table = {}
    for attack_byte, _ in sorted_attack_freq:
        candidates = [
            (byte, freq / artificial_freq[byte])
            for byte, freq in sorted_artificial_freq
        ]
        substitution_table[attack_byte] = candidates

    return substitution_table


def getAttackBodyPayload(path):
    f = open(path, "rb")
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if socket.inet_ntoa(ip.dst) == "192.150.11.111":
            tcp = ip.data
            if tcp.data == "":
                continue
            return tcp.data.rstrip()


def getArtificialPayload(path):
    f = open(path, "rb")
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if tcp.sport == 80 and len(tcp.data) > 0:
            return tcp.data
