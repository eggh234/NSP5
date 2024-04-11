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

    b_attack_payload = bytearray(attack_payload, "utf8")
    result = []
    xor_table = []
    # loop through all characters in the attaack payload


import numpy


import numpy


def substitute(attack_payload, substitution_table):
    # Convert the attack_payload to a bytearray for manipulation
    b_attack_payload = bytearray(attack_payload, "utf8")
    result = []
    xor_table = []

    i = 0  # Initialize loop counter for main while loop
    # Loop through each character in the attack payload using a while loop
    while i < len(attack_payload):
        char = attack_payload[i]  # Access the current character
        list_sub = substitution_table[
            char
        ]  # Get substitution list for the current character

        # If there is only one substitution option, use it directly
        if len(list_sub) == 1:
            temp, _ = list_sub[0]
            result.append(temp)
            xor_value = ord(char) ^ ord(temp)
            xor_table.append(chr(xor_value))
        else:
            total = sum(weight for _, weight in list_sub)
            sub_prob_list = {char: weight / total for char, weight in list_sub}
            replace_char_list, replace_char_prob_list = zip(*sub_prob_list.items())

            random_val = numpy.random.choice(
                replace_char_list, p=replace_char_prob_list
            )
            result.append(random_val)
            xor_value = ord(char) ^ ord(random_val)
            xor_table.append(chr(xor_value))

        i += 1  # Increment loop counter

    encrypted_result = "".join(result)
    return (xor_table, encrypted_result)


def getSubstitutionTable(artificial_payload, attack_payload):
    # You will need to generate a substitution table which can be used to encrypt the attack
    # body by replacing the most frequent byte in attack body by the most frequent byte in
    # artificial profile one by one

    # Note that the frequency for each byte is provided below in dictionay format.
    # Please check frequency.py for more details
    artificial_frequency = frequency(artificial_payload)

    attack_frequency = frequency(attack_payload)
    sorted_artificial_frequency = sorting(artificial_frequency)
    sorted_attack_frequency = sorting(attack_frequency)

    # number of distint characters in attack traffic
    attack_len = len(sorted_attack_frequency)

    # number of distincy characters in  normal/artificial
    normal_len = len(sorted_artificial_frequency)

    temp_sub_table = sorted_attack_frequency
    temp_values = [
        [] for i in range(attack_len)
    ]  # initialize list of attack_len elements

    for i in range(attack_len):
        temp_values[i].append(sorted_artificial_frequency[i])

    substitution_table = {}
    for i in range(len(temp_sub_table)):
        temp_total = temp_sub_table[
            i
        ]  # ex ('t',.44) , need to get t and place in new table
        temp_key = temp_total[0]
        temp_val = temp_total[1]
        substitution_table[temp_key] = temp_values[i]

    values_left = normal_len - attack_len
    # Loop through the remaining values in the artifical payload
    for j in range(values_left):
        temp_list_comparison = {}
        largest_ration = 0
        largest_ration_key = ""
        largest_ration_value = 0

        for i in range(attack_len):
            # get the original frequency/ divide by new frequency
            original_freq = (sorted_attack_frequency[i])[1]
            original_key = (sorted_attack_frequency[i])[0]
            total = 0
            # Get the total frequency
            for k in range(len(substitution_table[original_key])):
                total += ((substitution_table[original_key])[k])[1]

            new_freq = total
            comparison = round(original_freq / new_freq, 3)
            if comparison > largest_ration:
                largest_ration_key = original_key
                largest_ration_value = comparison
                largest_ration = comparison

            temp_list_comparison[original_key] = comparison

        substitution_table[largest_ration_key].append(
            sorted_artificial_frequency[attack_len + j]
        )

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
