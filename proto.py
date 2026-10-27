import json
import socket
import threading


def pack_fields(*fields):
    if any(
        not isinstance(value, str) or not value.isascii()
        for value in fields
    ):
        raise ValueError("field protokol harus berupa teks ASCII")

    return json.dumps(
        fields,
        ensure_ascii=True,
        separators=(",", ":")
    )


def unpack_fields(text, count=None):
    fields = json.loads(text)

    if not isinstance(fields, list) or any(
        not isinstance(value, str) or not value.isascii()
        for value in fields
    ):
        raise ValueError("format field protokol tidak valid")

    if count is not None and len(fields) != count:
        raise ValueError("jumlah field protokol tidak sesuai")

    return fields


class Channel:
    def __init__(self, sock):
        self.sock = sock
        self.reader = sock.makefile("rb")
        self.send_lock = threading.Lock()

    def send(self, *fields):
        with self.send_lock:
            data = pack_fields(*fields) + "\n"
            self.sock.sendall(data.encode("ascii"))

    def recv(self):
        line = self.reader.readline()

        if not line:
            return None

        return unpack_fields(line.decode("ascii"))

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        for closer in (self.reader.close, self.sock.close):
            try:
                closer()
            except OSError:
                pass


def dial(host, port, source_ip=None, timeout=10):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        if source_ip and source_ip != "0.0.0.0":
            sock.bind((source_ip, 0))

        sock.connect((host, port))

    except OSError:
        sock.close()
        raise

    return sock


def listen(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(8)
    return server


def split_address(text, default_port):
    if ":" in text:
        host, port = text.rsplit(":", 1)
        return host, int(port)

    return text, default_port