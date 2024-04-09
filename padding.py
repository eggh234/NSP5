from frequency import frequency


def padding(artificial_payload, raw_payload):
    """
    Append the byte with the largest byte frequency difference to raw_payload.
    If a byte is only in raw_payload, its frequency is used as the difference.
    Each call to this function pads only one byte at a time.
    """
    # Calculate the frequency of each byte in both payloads
    artificial_freq = frequency(artificial_payload)
    raw_freq = frequency(raw_payload)

    # Determine the byte with the largest difference
    max_diff = -1
    padding_byte = None

    # Check each byte in the raw_payload
    for byte, raw_byte_freq in raw_freq.items():
        artificial_byte_freq = artificial_freq.get(byte, 0)

        # If the byte is not in artificial_payload, use the raw_payload frequency
        diff = (
            raw_byte_freq
            if byte not in artificial_freq
            else artificial_byte_freq - raw_byte_freq
        )

        # Find the byte with the max diff to use for padding
        if diff > max_diff:
            max_diff = diff
            padding_byte = byte

    # Ensure padding_byte is a byte for appending
    padding_byte = (
        padding_byte if isinstance(padding_byte, bytes) else bytes([padding_byte])
    )

    # Pad the raw_payload if it's shorter than the artificial_payload
    if len(raw_payload) < len(artificial_payload):
        # Append one byte of padding
        raw_payload += padding_byte

    return raw_payload

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload.
    # Note: only consider the differences when artificial profile has higher frequency.
    # Depending upon the difference, call raw_payload.append

    # Your code here ...
