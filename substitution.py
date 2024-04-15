#!/usr/bin/env python3

import struct
import math
import dpkt
import socket
import numpy
from collections import Counter
from frequency import *


def substitute(attack_payload, substitution_table):
    # Convert the attack payload to a mutable bytearray for easier manipulation.
    b_attack_payload = bytearray(attack_payload, "utf8")
    result = []
    xor_table = []

    i = 0
    # Iterate through the byte array representation of the attack payload.
    while i < len(b_attack_payload):
        current_byte = b_attack_payload[i]
        list_sub = substitution_table[
            chr(current_byte)
        ]  # Access substitution using character representation.
        replacement_list = []
        replacement_prob_list = []

        # Handling the substitution based on the size of the list_sub.
        while len(list_sub) == 1:
            # Directly use the single substitution character.
            temp = list_sub[0][0]
            result.append(temp)
            # XOR the original and substituted characters to encrypt/decrypt.
            xor_value = current_byte ^ ord(temp)
            xor_table.append(chr(xor_value))
            break  # Break to mimic the functionality of an 'if' statement.

        # When there are multiple options, calculate the best substitution based on their probabilities.
        if len(list_sub) > 1:
            total_weight = sum(weight for _, weight in list_sub)
            x = 0
            # Build replacement lists for random choice selection.
            while x < len(list_sub):
                char, weight = list_sub[x]
                replacement_list.append(char)
                replacement_prob_list.append(weight / total_weight)
                x += 1

            # Choose a substitute character based on the weighted probabilities.
            random_val = numpy.random.choice(replacement_list, p=replacement_prob_list)
            result.append(random_val)
            xor_value = current_byte ^ ord(random_val)
            xor_table.append(chr(xor_value))

        i += 1  # Move to the next byte in the payload.

    return (xor_table, "".join(result))


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
