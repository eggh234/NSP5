#!/usr/bin/env python3

import struct
import math
import dpkt
import socket
from collections import Counter
from frequency import *


def substitute(attack_payload, substitution_table):
    b_attack_payload = bytearray(attack_payload.encode("utf-8"))
    result = bytearray()
    xor_table = bytearray()
    # Using the substitution table you generated to encrypt attack payload
    # Note that you also need to generate a xor_table which will be used to decrypt
    # the attack_payload
    # i.e. (encrypted attack payload) XOR (xor_table) = (original attack payload)

    for byte in b_attack_payload:
        # Use the substitution table to find the replacement byte
        substituted_byte = substitution_table.get(byte, byte)
        result.append(substituted_byte)

        # Prepare the xor_table for decryption
        xor_byte = byte ^ substituted_byte
        xor_table.append(xor_byte)
    # Based on your implementattion of substitution table, please prepare result
    # and xor_table as output
    return (bytes(xor_table), bytes(result))


def getSubstitutionTable(artificial_payload, attack_payload):
    # Calculate the frequency of each byte in both payloads
    artificial_frequency = frequency(artificial_payload.encode("utf-8"))
    attack_frequency = frequency(attack_payload.encode("utf-8"))

    # Sort the bytes by their frequency, from most to least frequent
    sorted_artificial_frequency = sorting(artificial_frequency)
    sorted_attack_frequency = sorting(attack_frequency)

    substitution_table = {}
    used_artificial_bytes = set()

    # Iterate over the sorted frequencies of attack payload bytes
    for attack_byte, _ in sorted_attack_frequency:
        for artificial_byte, _ in sorted_artificial_frequency:
            # Find the highest frequency artificial byte that hasn't been used yet
            if artificial_byte not in used_artificial_bytes:
                # Map the attack byte to this artificial byte
                substitution_table[attack_byte] = artificial_byte
                used_artificial_bytes.add(artificial_byte)
                break
    # Make sure your substitution table can be used in
    # substitute(attack_payload, subsitution_table)
    print(substitution_table)
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
