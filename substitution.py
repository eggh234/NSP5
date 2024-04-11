#!/usr/bin/env python3

import struct
import math
import dpkt
import socket
import numpy
from collections import Counter
from frequency import *


def substitute(attack_payload, substitution_table):
    b_attack_payload = bytearray(attack_payload, "utf8")
    result = []
    xor_table = []

    i = 0
    while i < len(attack_payload):
        list_sub = substitution_table[
            attack_payload[i]
        ]  # Get the substitution list for the current character.
        replace_char_list = []
        replace_char_prob_list = []

        # If there's only one substitution option, use it directly.
        if len(list_sub) == 1:
            temp = list_sub[0][0]  # The character to substitute.
            result.append(temp)
            # Compute XOR for the original and substituted character to facilitate decryption.
            or1 = ord(attack_payload[i])
            or2 = ord(temp)
            final_xord = or1 ^ or2
            xor_table.append(chr(final_xord))
        else:
            # Calculate total weight for the substitution characters.
            j = 0
            total = 0
            while j < len(list_sub):
                total += list_sub[j][1]
                j += 1

            # Calculate probabilities for each substitution character.
            x = 0
            while x < len(list_sub):
                char, weight = list_sub[x]
                replace_char_list.append(char)
                replace_char_prob_list.append(weight / total)
                x += 1

            # Select a character based on calculated probabilities.
            random_val = numpy.random.choice(
                a=replace_char_list, p=replace_char_prob_list
            )
            result.append(random_val)
            or1 = ord(attack_payload[i])
            or2 = ord(random_val)
            final_xord = or1 ^ or2
            xor_table.append(chr(final_xord))

        i += 1

    return (xor_table, result)


def getSubstitutionTable(artificial_payload, attack_payload):
    # Generate frequencies for artificial and attack payloads.
    artificial_frequency = frequency(artificial_payload)
    attack_frequency = frequency(attack_payload)
    # Sort frequencies to identify the most frequent bytes.
    sorted_artificial_frequency = sorting(artificial_frequency)
    sorted_attack_frequency = sorting(attack_frequency)

    attack_len = len(sorted_attack_frequency)
    normal_len = len(sorted_artificial_frequency)

    temp_sub_table = sorted_attack_frequency
    temp_values = [[] for _ in range(attack_len)]

    i = 0
    while i < attack_len:
        temp_values[i].append(sorted_artificial_frequency[i])
        i += 1

    substitution_table = {}
    i = 0
    while i < len(temp_sub_table):
        temp_total = temp_sub_table[i]
        temp_key = temp_total[0]
        substitution_table[temp_key] = temp_values[i]
        i += 1

    # Handle remaining bytes in the artificial payload not mapped yet.
    values_left = normal_len - attack_len
    j = 0
    while j < values_left:
        largest_ratio = 0
        largest_ratio_key = ""
        i = 0
        while i < attack_len:
            original_freq = sorted_attack_frequency[i][1]
            original_key = sorted_attack_frequency[i][0]
            total = sum(val[1] for val in substitution_table[original_key])

            new_freq = total
            comparison = round(original_freq / new_freq, 3)
            # Identify the byte with the largest frequency ratio discrepancy.
            if comparison > largest_ratio:
                largest_ratio_key = original_key
                largest_ratio = comparison
            i += 1

        # Add additional artificial bytes to the substitution table for the identified key.
        substitution_table[largest_ratio_key].append(
            sorted_artificial_frequency[attack_len + j]
        )
        j += 1

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
