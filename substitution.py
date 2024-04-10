#!/usr/bin/env python3

import struct
import math
import dpkt
import socket
import numpy
from collections import Counter
from frequency import *


def substitute(attack_payload, substitution_table):
    # Using the substitution table you generated to encrypt attack payload
    # Note that you also need to generate a xor_table which will be used to decrypt
    # the attack_payload
    # i.e. (encrypted attack payload) XOR (xor_table) = (original attack payload)
    # b_attack_payload = bytearray(attack_payload, "utf8")

    # Convert the attack_payload to a bytearray for byte-wise operations
    b_attack_payload = bytearray(attack_payload, "utf-8")
    result = bytearray()
    xor_table = bytearray()

    for byte in b_attack_payload:
        # Retrieve the substitution list for the current byte
        substitutions = substitution_table[byte]

        # Choose a replacement byte based on the substitution probabilities
        choices, weights = zip(
            *substitutions
        )  # Unpack substitutions into choices and their weights
        chosen_byte = numpy.random.choice(choices, p=weights)

        # Append the chosen byte to the result
        result.append(chosen_byte)

        # Compute and append the XOR of the original and chosen byte for the xor_table
        xor_value = byte ^ chosen_byte
        xor_table.append(xor_value)

    # Convert the result and xor_table to their string representations if necessary
    # Depending on how you want to handle the output, this step may need adjustments
    return (
        bytes(xor_table).decode("utf-8", "replace"),
        result.decode("utf-8", "replace"),
    )


def getSubstitutionTable(artificial_payload, attack_payload):
    # You will need to generate a substitution table which can be used to encrypt the attack
    # body by replacing the most frequent byte in attack body by the most frequent byte in
    # artificial profile one by one

    # Note that the frequency for each byte is provided below in dictionay format.
    # Please check frequency.py for more details
    artificial_freq = frequency(artificial_payload)
    attack_freq = frequency(attack_payload)

    # Sort the frequencies in descending order
    sorted_artificial_freq = sorted(
        artificial_freq.items(), key=lambda x: x[1], reverse=True
    )
    sorted_attack_freq = sorted(attack_freq.items(), key=lambda x: x[1], reverse=True)

    substitution_table = {}
    attack_len = len(sorted_attack_freq)
    normal_len = len(sorted_artificial_freq)

    # Assign initial substitutions from the top frequencies
    for i in range(attack_len):
        attack_byte = sorted_attack_freq[i][0]
        # Start with the most frequent artificial byte not already used
        for art_byte, _ in sorted_artificial_freq:
            if not any(art_byte in subs for subs in substitution_table.values()):
                if not substitution_table.get(attack_byte):
                    substitution_table[attack_byte] = [
                        (art_byte, artificial_freq[art_byte])
                    ]
                else:
                    substitution_table[attack_byte].append(
                        (art_byte, artificial_freq[art_byte])
                    )
                break

    # For remaining artificial bytes, distribute among attack bytes based on need
    for j in range(attack_len, normal_len):
        art_byte, art_freq = sorted_artificial_freq[j]
        # Find the attack byte with the least total assigned frequency
        least_assigned_byte = min(
            substitution_table.keys(),
            key=lambda k: sum(freq for _, freq in substitution_table[k]),
        )
        substitution_table[least_assigned_byte].append((art_byte, art_freq))

    # Normalize frequencies in the substitution table
    for attack_byte in substitution_table:
        total_freq = sum(freq for _, freq in substitution_table[attack_byte])
        substitution_table[attack_byte] = [
            (byte, freq / total_freq) for byte, freq in substitution_table[attack_byte]
        ]
    # Make sure your substitution table can be used in
    print(substitution_table)
    # substitute(attack_payload, substitution_table)
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
