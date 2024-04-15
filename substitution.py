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
        replacement_list = []
        replacement_prob_list = []

        # If there's only one substitution option, use it directly.
        if len(list_sub) == 1:
            temp = list_sub[0][0]  # The character to substitute.
            result.append(temp)
            # Compute XOR for the original and substituted character to facilitate decryption.
            or1 = ord(attack_payload[i])
            or2 = ord(temp)
            Xord_value = or1 ^ or2
            xor_table.append(chr(Xord_value))
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
                replacement_list.append(char)
                replacement_prob_list.append(weight / total)
                x += 1

            # Select a character based on calculated probabilities.
            random_val = numpy.random.choice(
                a=replacement_list, p=replacement_prob_list
            )
            result.append(random_val)
            or1 = ord(attack_payload[i])
            or2 = ord(random_val)
            Xord_value = or1 ^ or2
            xor_table.append(chr(Xord_value))

        i += 1

    return (xor_table, result)


def getSubstitutionTable(artificial_payload, attack_payload):
    # Generate and sort frequencies to identify the most frequent bytes.
    artificial_frequency = frequency(artificial_payload)
    attack_frequency = frequency(attack_payload)
    sorted_artificial_frequency = sorting(artificial_frequency)
    sorted_attack_frequency = sorting(attack_frequency)

    attack_len = len(sorted_attack_frequency)
    normal_len = len(sorted_artificial_frequency)

    # Create a substitution table mapping the most frequent attack bytes to artificial bytes directly.
    substitution_table = {
        item[0]: [sorted_artificial_frequency[i]]
        for i, item in enumerate(sorted_attack_frequency)
    }

    # Determine the number of additional artificial bytes to map.
    remaining_values = normal_len - attack_len

    # Use a modified approach to distribute remaining artificial bytes.
    j = 0
    while j < remaining_values:
        # Iterate to find the least total mapped frequency key (to balance the distribution).
        i = 0
        smallest_total_freq = float("inf")
        key_for_append = None
        while i < len(substitution_table):
            key, sublist = list(substitution_table.items())[i]
            total_mapped_frequency = sum(item[1] for item in sublist)
            while total_mapped_frequency < smallest_total_freq:
                smallest_total_freq = total_mapped_frequency
                key_for_append = key
                break  # Break while if the condition is met to mimic 'if' logic
            i += 1

        # Append the next artificial frequency item to the least mapped key.
        while (
            key_for_append and j < remaining_values
        ):  # Guard condition to mimic 'if' behavior with 'while'
            substitution_table[key_for_append].append(
                sorted_artificial_frequency[attack_len + j]
            )
            break  # Ensure it runs only once like an 'if'
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
