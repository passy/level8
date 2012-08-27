import SocketServer

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 50011


class WebhookServer(SocketServer.TCPServer):

    def verify_request(self, request, client_address):
        print("client_address: {}".format(client_address))
        return True


class WebhookHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024)
        print("data: {}".format(data))



class Client(object):
    """Client trying to break the password that is supposed to be 4 * 3
    characters, devided into same-length chunks.
    """

    PASSWORD_LENGTH = 12
    CHUNKS = 4

    def __init__(self):
        self.chunk = 0
        self.counter = 0
        self.verified_chunks = []

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


if __name__ == "__main__":
    server = WebhookServer((SERVER_HOST, SERVER_PORT), WebhookHandler)
    server.serve_forever()
