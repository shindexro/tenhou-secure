import json
import logging
import socket
import sys

from bs4 import BeautifulSoup
from datetime import date, timedelta


def tag_to_dict(tag_string):
    soup = BeautifulSoup(tag_string, "html.parser")
    tag = soup.find()
    (tag_name, *_) = tag_string.split(maxsplit=1)
    tag_name = tag_name[1:]
    data = dict()
    data["tag"] = tag_name
    data.update(tag.attrs)
    return data


def json_to_dict(json_string):
    return json.loads(json_string)


def dict_to_xml(data):
    if not isinstance(data, dict):
        return str(data)

    tag_name = data["tag"]
    attributes = " ".join(['{}="{}"'.format(k, v) for k, v in data.items() if k != "tag" and k != "childNodes"])
    head = f"{tag_name} {attributes}" if attributes else tag_name

    if "childNodes" in data:
        children = "".join(dict_to_xml(child) for child in data["childNodes"])
        return f"<{head}{attributes}>{children}</{tag_name}>"
    else:
        return f"<{head}/>"


def dict_to_json(data):
    return json.dumps(data, separators=(",", ":"))


def fake_expire_date(seed):
    seed = sum([ord(c) for c in seed])
    month = seed % 12 + 1
    day = seed % 28 + 1
    expire_date = date(date.today().year + 1, month, day)
    if date.today() + timedelta(days=80) < expire_date:
        expire_date = date(date.today().year + 2, month, day)
    return expire_date


def try_server_bind(server_socket, host, port):
    try:
        server_socket.bind((host, port))
    except Exception as e:
        print("problem on bind: %r" % e)
        print("[!!] Failed to listen on %s:%d" % (host, port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)


def debug_packet(packet):
    tcp = packet.tcp
    logging.debug(
        "%s: %s, seq=%s, ack=%s, len=%s, [%s %s %s]",
        " IN" if packet.is_inbound else "OUT",
        packet.payload,
        tcp.seq_num,
        tcp.ack_num,
        len(packet.payload),
        "SYN" if tcp.syn else "",
        "ACK" if tcp.ack else "",
        "PSH" if tcp.psh else "",
    )


HEX_FILTER = "".join([(len(repr(chr(i))) == 3) and chr(i) or "." for i in range(256)])


def hexdump(src, length=16, show=True):
    if isinstance(src, bytes):
        src = src.decode()

    results = list()
    for i in range(0, len(src), length):
        word = src[i: i + length]
        printable = word.translate(HEX_FILTER)
        hexa = "".join([f"{ord(c):02X}" for c in word])
        hexwidth = length * 3
        results.append(f"{i:04x} {hexa:<{hexwidth}} {printable}")
        if show:
            for line in results:
                print(line)
        return results


def show_packet(packet):
    flags = tcp_flags(packet)
    print(f"{' IN' if packet.is_inbound else 'OUT'}: "
          f"{packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}, "
          f"SEQ={packet.tcp.seq_num}, ACK={packet.tcp.ack_num}, len={len(packet.payload)}, "
          f"[{' '.join(flags)}]"
          f"{'[LOOPBACK]' if packet.is_loopback else ''}")
    print(packet.payload)


def tcp_flags(packet):
    flags = list()
    if packet.tcp.ns:
        flags.append(' NS')
    if packet.tcp.cwr:
        flags.append('CWR')
    if packet.tcp.ece:
        flags.append('ECE')
    if packet.tcp.urg:
        flags.append('URG')
    if packet.tcp.ack:
        flags.append('ACK')
    if packet.tcp.psh:
        flags.append('PSH')
    if packet.tcp.rst:
        flags.append('RST')
    if packet.tcp.syn:
        flags.append('SYN')
    if packet.tcp.fin:
        flags.append('FIN')
    return flags


def get_local_ip():
    # Auto-Detect local IP. This is required as re-injecting to 127.0.0.1 does not work.
    # https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def int_to_base52(num):
    base52 = ""
    while num:
        remainder = num % 52
        c = (
            chr(ord("A") + remainder)
            if remainder < 26
            else chr(ord("a") + remainder - 26)
        )
        base52 += c
        num //= 52
    return base52[::-1]


def encode_ln_attribute(attribute):
    """
    Takes a LN message attribute of in the form like "1,,,,3,1,,", i.e. a list of integers
    Then encodes the attribute into the form ([a-zA-Z]+[0-9]+)+, [a-zA-Z]+ is the corresponding base-52 representation
    of each integer, and the trailing number [0-9]+ means how many same integers appear consecutively.
    E.g. the encoding "a2B3" corresponds to "26,26,1,1,1"
    The return value is not the most compact encoding.
    """
    return "1".join([int_to_base52(int(i)) if i else "A" for i in attribute.split(",")])
