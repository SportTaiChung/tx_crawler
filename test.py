import json
import urllib.parse
from hashlib import md5
import base64
import xxtea


def decrypt_data(encrypted_parts: list):
    decrypted_data = None
    hash_key = md5(encrypted_parts[3][:-1].encode('utf-8')).hexdigest()
    encryption_type = encrypted_parts[2]
    encrypted_info = encrypted_parts[1]
    encrypted_data = encrypted_parts[0]
    if encryption_type == '2':
        decrypted_info = json.loads(xxtea_decrypt(encrypted_info, hash_key))
        decrypted_data = decrypt_type2(encrypted_data, decrypted_info, hash_key)
    elif encryption_type == '3':
        decrypted_info = json.loads(xxtea_decrypt(encrypted_info, hash_key))
        decrypted_data = decrypt_type3(encrypted_data, decrypted_info, hash_key)
    elif encryption_type == '0':
        decrypted_info = json.loads(xxtea_decrypt(encrypted_info, hash_key))
        decrypted_data = decrypt_type0(encrypted_data, decrypted_info, hash_key)
    elif encryption_type == '4':
        decrypted_data = json.loads(xxtea_decrypt(encrypted_data, hash_key))
    return decrypted_data

def decrypt_type2(encrypted_data, info, key):
    decrypted_data = []
    part1_1_len = int(info['part1_1'])
    part1_2_len = int(info['part1_2'])
    part1_3_len = int(info['part1_3'])
    part1_len = int(info['part1'])
    part2_1_len = int(info['part2_1'])
    part2_2_len = int(info['part2_2'])
    part2_3_len = int(info['part2_3'])
    data_parts = []
    start_pos = 0
    # part1
    for part_len in (part1_1_len, part1_2_len, part1_3_len):
        part = encrypted_data[start_pos:start_pos+part_len]
        data_parts.append(part)
        start_pos += part_len
    start_pos = part1_len
    # part2
    for part_len in (part2_1_len, part2_2_len, part2_3_len):
        part = encrypted_data[start_pos:start_pos+part_len]
        data_parts.append(part)
        start_pos += part_len
    # last
    data_parts.append(encrypted_data[start_pos:])
    for idx, part in enumerate(data_parts):
        if idx % 2 == 0:
            decrypted_data.append(xxtea_decrypt(part, key))
        else:
            decrypted_data.append(urllib.parse.unquote(part))
    return json.loads(''.join(decrypted_data))

def decrypt_type3(encrypted_data, info, key):
    decrypted_data = []
    part1_1_len = int(info['part1_1'])
    part1_2_len = int(info['part1_2'])
    part1_3_len = int(info['part1_3'])
    part1_len = int(info['part1'])
    part2_1_len = int(info['part2_1'])
    part2_2_len = int(info['part2_2'])
    part2_3_len = int(info['part2_3'])
    part3_1_len = int(info['part3_1'])
    part3_2_len = int(info['part3_2'])
    data_parts = []
    start_pos = 0
    # part1
    for part_len in (part1_1_len, part1_2_len, part1_3_len):
        part = encrypted_data[start_pos:start_pos+part_len]
        data_parts.append(part)
        start_pos += part_len
    start_pos = part1_len
    # part2
    for part_len in (part2_1_len, part2_2_len, part2_3_len):
        part = encrypted_data[start_pos:start_pos+part_len]
        data_parts.append(part)
        start_pos += part_len
    # part3
    for part_len in (part3_1_len, part3_2_len):
        part = encrypted_data[start_pos:start_pos+part_len]
        data_parts.append(part)
        start_pos += part_len
    # last
    data_parts.append(encrypted_data[start_pos:])
    for idx, part in enumerate(data_parts):
        if idx % 2 == 1:
            decrypted_data.append(xxtea_decrypt(part, key))
        else:
            decrypted_data.append(urllib.parse.unquote(part))
    return json.loads(''.join(decrypted_data))

def decrypt_type0(encrypted_data, info, key):
    decrypted_data = []
    part1_1_len = int(info['part1_1'])
    part1_2_len = int(info['part1_2'])
    part1_3_len = int(info['part1_3'])
    part1_len = int(info['part1'])
    part2_len = int(info['part2'])
    part3_1_len = int(info['part3_1'])
    part3_2_len = int(info['part3_2'])
    part3_3_len = int(info['part3_3'])
    data_parts = []
    start_pos = 0
    # part1
    for part_len in (part1_1_len, part1_2_len, part1_3_len):
        part = encrypted_data[start_pos:start_pos+part_len]
        data_parts.append(part)
        start_pos += part_len
    start_pos = part1_len
    # part2
    for part_len in (part2_len, ):
        part = encrypted_data[start_pos:start_pos+part_len]
        data_parts.append(part)
        start_pos += part_len
    # part3
    for part_len in (part3_1_len, part3_2_len, part3_3_len):
        part = encrypted_data[start_pos:start_pos+part_len]
        data_parts.append(part)
        start_pos += part_len
    for idx, part in enumerate(data_parts):
        if idx % 2 == 1:
            decrypted_data.append(xxtea_decrypt(part, key))
        else:
            decrypted_data.append(urllib.parse.unquote(part))
    return json.loads(''.join(decrypted_data))

def xxtea_decrypt(data, key):
    base64_data = base64.b64decode(data)
    decrypted_data = xxtea.decrypt_utf8(base64_data, key)
    decrypted_data = base64.b64decode(decrypted_data).decode()
    return decrypted_data


if __name__ == '__main__':
    with open('data.txt') as f:
        raw_data = f.read()
    parts = raw_data.split('〄')
    if len(parts) == 4:
        real_data = decrypt_data(parts)
        print(real_data)
