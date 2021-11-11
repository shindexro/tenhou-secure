import logging
import select
import socket
import sys
import threading
from urllib.parse import unquote

import websocket

from util import (
    tag_to_dict,
    dict_to_json,
    json_to_dict,
    dict_to_xml,
    try_server_bind,
    fake_expire_date, encode_ln_attribute,
)


class TenhouConnectionPair:
    def __init__(self, client_socket):
        self.client_socket = client_socket
        self.server_socket = None
        self.web_socket = None
        self.web_socket_connected = False
        self.sent_first_pxr = False
        self.spectate_game_id = None

    def start(self):
        logging.info("[*] Starting a pair of tenhou connection.")
        threading.Thread(target=self.create_tenhou_connection).start()

        while not self.web_socket_connected:
            pass

        while self.web_socket_connected:
            readables, _, _ = select.select([self.client_socket], [], [])
            if self.client_socket in readables:
                buffer = self.client_socket.recv(4096)
                for message in buffer.split(b"\x00"):
                    self.send_to_tenhou(message)

    def create_tenhou_connection(self):
        self.web_socket = websocket.WebSocketApp(
            "wss://b-ww.mjv.jp",
            header={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
                "Accept": "*/*",
                "Accept-Language": "ja;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
            },
            on_message=(lambda _, p: self.send_to_client(p)),
            on_open=(lambda _: self.on_open_tenhou_connection()),
            on_close=(lambda _, c, m: self.on_close_tenhou_connection(c, m)),
        )
        self.web_socket.run_forever(
            origin="https://tenhou.net",
            host="b-ww.mjv.jp",
            ping_interval=0.7,
            skip_utf8_validation=True,
        )

    def on_open_tenhou_connection(self):
        logging.info("[*] Connected to tenhou wss server.")
        self.web_socket_connected = True

    def on_close_tenhou_connection(self, status_code, message):
        logging.info(f"[!!] Tenhou connection closed, status={status_code}: {message}")
        self.web_socket_connected = False
        sys.exit()

    def send_to_tenhou(self, payload):
        """
        Mimic the response format of the tenhou.net/3/ web client, and
        modify the expiry date from the HELO message to trick the Windows client.
        """
        if not payload:
            return
        logging.info(payload)

        payload = payload.decode("UTF-8")
        data = tag_to_dict(payload)
        messages = []

        if data["tag"] == "Z":
            messages.append("<Z/>")

        elif data["tag"] == "D":
            data["p"] = int(data["p"])
            messages.append(dict_to_json(data))

        elif data["tag"] == "N":
            if "type" in data:
                data["type"] = int(data["type"])
            if "hai" in data:
                data["hai"] = int(data["hai"])
            messages.append(dict_to_json(data))

        elif data["tag"] == "REACH":
            del data["hai"]
            messages.append(dict_to_json(data))

        elif data["tag"] == "HELO":
            # tid identifies the client type, w0=windows
            if "tid" in data:
                del data["tid"]
            messages.append(dict_to_json(data))

        elif data["tag"] == "PXR":
            pxr_value = data["v"]
            if not self.sent_first_pxr:
                del data["v"]
                data["V"] = pxr_value
                self.sent_first_pxr = True
            else:
                data["v"] = pxr_value
            messages.append(dict_to_xml(data))

        elif data["tag"] == "BYE":
            messages.append(dict_to_xml(data))

        elif data["tag"] == "CHAT" and unquote(data["text"]).startswith("/wg "):
            self.spectate_game_id = unquote(data["text"])[4:]
            wg_data = {"tag": "WG", "id": self.spectate_game_id, "tw": 0}
            messages.append("<BYE/>")
            messages.append('{"tag":"HELO","name":"NoName","sx":"M"}')
            messages.append(dict_to_json(wg_data))

        elif data["tag"] == "REINIT":
            wg_data = {"tag": "WG", "id": self.spectate_game_id, "tw": 0}
            messages.append("<BYE/>")
            messages.append('{"tag":"HELO","name":"NoName","sx":"M"}')
            messages.append(dict_to_json(wg_data))

        elif data["tag"] == "CHAT":
            # Drop outbound chat messages
            # self.client_socket.send(b'<CHAT text="#GUEST CHAT DISABLED"/>')
            pass

        else:
            messages.append(dict_to_json(data))

        for message in messages:
            logging.info("[==>] Sending payload to tenhou: %s" % message)
            self.web_socket.send(message.encode("UTF-8"))

    def send_to_client(self, payload):
        if not payload:
            return
        logging.info(f"{payload}")
        if payload[0] == "{":
            data = json_to_dict(payload)

            if data["tag"] == "LN":
                data["n"] = encode_ln_attribute(data["n"])
                data["j"] = encode_ln_attribute(data["j"])
                data["g"] = encode_ln_attribute(data["g"])

            tag = dict_to_xml(data)
        else:
            tag = payload
        logging.info("[<==] Sending payload to client: %s" % tag)
        tag += "\x00"
        self.client_socket.send(tag.encode("UTF-8"))


class WebSocketProxy:
    def __init__(self, proxy_host, proxy_port):
        super().__init__()
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try_server_bind(server_socket, self.proxy_host, self.proxy_port)
        server_socket.listen(5)

        while True:
            client_socket, _ = server_socket.accept()
            client_socket.setblocking(False)
            threading.Thread(target=TenhouConnectionPair(client_socket).start).start()
