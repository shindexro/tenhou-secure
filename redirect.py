import logging
import threading

import pydivert


class Redirect:
    def __init__(self, server_host, server_port, proxy_host, proxy_port):
        self.client_host = None
        self.client_port = 0
        self.server_host = server_host
        self.server_port = server_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def handle(self):
        """
        Redirect local outbound packet to server_host:server_port to proxy_host:proxy_port.
        Packets sent by the proxy to the client should appear as if they are directly sent from the server,
        i.e. the proxy is invisible to the client.
        """
        # Reflect [client -> server] into [client -> proxy]
        threading.Thread(target=self.reflect_client_to_server).start()
        while not self.client_host:
            continue
        # Reflect [proxy -> client] into [server -> client]
        threading.Thread(target=self.reflect_proxy_to_client).start()

    def reflect_client_to_server(self):
        """
        Reflect packets from [client -> server] into [client -> proxy].
        """
        packet_filter = f"tcp and outbound and" \
                        f" (ip.DstAddr == {self.server_host} and tcp.DstPort == {self.server_port}" \
                        f" and (ip.SrcAddr != {self.proxy_host} or tcp.SrcPort != {self.proxy_port}))"

        with pydivert.WinDivert(filter=packet_filter) as w:
            logging.info(f"[*] Ready to reflect [client -> {self.server_host}:{self.server_port}] packets.")
            for packet in w:
                self.client_port = packet.src_port
                self.client_host = packet.src_addr
                packet.dst_addr = self.proxy_host
                packet.dst_port = self.proxy_port
                packet.direction = pydivert.Direction.INBOUND
                w.send(packet)

    def reflect_proxy_to_client(self):
        """
        Reflect packets from [proxy -> client] into [server -> client].
        """
        packet_filter = f"tcp and outbound and" \
                        f" (ip.DstAddr == {self.client_host} and tcp.DstPort == {self.client_port}" \
                        f" and ip.SrcAddr == {self.proxy_host} or tcp.SrcPort == {self.proxy_port})"

        with pydivert.WinDivert(filter=packet_filter) as w:
            logging.info("[*] Ready to reflect [proxy -> client] packets.")
            for packet in w:
                packet.src_addr = self.server_host
                packet.src_port = self.server_port
                packet.direction = pydivert.Direction.INBOUND
                w.send(packet)


if __name__ == '__main__':
    from main import TENHOU_HOST, TENHOU_PORT, WSS_PROXY_HOST, WSS_PROXY_PORT

    for host in TENHOU_HOST:
        redirect = Redirect(host, TENHOU_PORT, WSS_PROXY_HOST, WSS_PROXY_PORT)
        redirect_thread = threading.Thread(target=redirect.handle)
        redirect_thread.start()
