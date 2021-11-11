"""
Encrypt tenhou traffics.
Intercepts TCP packets from the windows tenhou client and establish WSS connection with tenhou instead.

"""
import logging
import threading
from datetime import datetime

from redirect import Redirect
from tenhou import WebSocketProxy
from util import get_local_ip

LOGGING_LEVEL = logging.ERROR
TENHOU_HOST = ["160.16.213.80", "160.16.141.68", "133.242.10.78"]
TENHOU_PORT = 10080
WSS_PROXY_HOST = get_local_ip()
WSS_PROXY_PORT = 24442


def main():
    logging.basicConfig(
        level=LOGGING_LEVEL,
        format='%(relativeCreated)6d %(threadName)s %(message)s',
        filename=f"D:\\Projects\\tenhou_cracker\\logs\\{datetime.now().strftime('%Y%m%d-%H%M%S')}.log",
        filemode="w",
    )

    for host in TENHOU_HOST:
        redirect = Redirect(host, TENHOU_PORT, WSS_PROXY_HOST, WSS_PROXY_PORT)
        redirect_thread = threading.Thread(target=redirect.handle)
        redirect_thread.start()

    wss_proxy = WebSocketProxy(WSS_PROXY_HOST, WSS_PROXY_PORT)
    proxy_thread = threading.Thread(target=wss_proxy.start)
    proxy_thread.start()

    print("Started. Please proceed to open the client.")


if __name__ == "__main__":
    main()
