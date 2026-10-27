import argparse
import secrets
import string
import threading

from aes import check_key, encrypt_text
from proto import Channel, listen, pack_fields


ALPHABET = string.ascii_letters + string.digits

HELP = (
    "perintah KDC:\n"
    "  keys                     daftar ID terdaftar\n"
    "  setkey <id> <key>        ubah/daftarkan master key\n"
    "  sessionkey <key|auto>    atur session key atau kembali acak\n"
    "  quit                     keluar"
)


class KDC:
    def __init__(self):
        self.keys = {}
        self.forced_session_key = None
        self.lock = threading.Lock()
        self.print_lock = threading.Lock()

    def log(self, text):
        with self.print_lock:
            print(
                f"\r{text}\nkdc> ",
                end="",
                flush=True
            )

    def set_key(self, ident, key):
        if not ident or not ident.isascii():
            raise ValueError(
                "ID harus berupa teks ASCII yang tidak kosong"
            )

        check_key(key)

        with self.lock:
            self.keys[ident] = key

    def new_session_key(self):
        with self.lock:
            if self.forced_session_key:
                return self.forced_session_key

        return "".join(
            secrets.choice(ALPHABET)
            for _ in range(16)
        )

    def handle(self, sock, addr):
        channel = Channel(sock)

        try:
            sock.settimeout(15)
            request = channel.recv()

            if (
                not request
                or request[0] != "REQ"
                or len(request) != 4
            ):
                channel.send("ERR", "format request salah")
                return

            _, id_a, id_b, nonce = request

            if id_a == id_b:
                channel.send(
                    "ERR",
                    "ID peminta dan tujuan harus berbeda"
                )
                return

            with self.lock:
                key_a = self.keys.get(id_a)
                key_b = self.keys.get(id_b)

            if key_a is None or key_b is None:
                self.log(
                    f"[KDC] request dari {addr[0]} ditolak: "
                    f"ID tidak terdaftar ({id_a}, {id_b})"
                )
                channel.send("ERR", "ID tidak terdaftar")
                return

            self.log(
                f"[KDC] step 1 dari {addr[0]}: "
                f"{id_a} -> KDC | "
                f"ID_A={id_a} ID_B={id_b} N1={nonce}"
            )

            session_key = self.new_session_key()

            # Dua ciphertext terpisah mengikuti diagram tugas.
            ticket = encrypt_text(
                key_b,
                pack_fields(session_key, id_a)
            )

            reply = encrypt_text(
                key_a,
                pack_fields(
                    session_key,
                    id_a,
                    id_b,
                    nonce
                )
            )

            channel.send("RESP", reply, ticket)

            self.log(
                f"[KDC] step 2 ke {addr[0]}\n"
                f"      Ks      = {session_key}\n"
                f"      ticket  = E(Kb, Ks||ID_A) = {ticket}\n"
                f"      reply   = "
                f"E(Ka, Ks||ID_A||ID_B||N1) = {reply}"
            )

        except (OSError, ValueError) as error:
            self.log(
                f"[KDC] error melayani {addr[0]}: {error}"
            )

        finally:
            channel.close()

    def serve(self, server):
        while True:
            try:
                conn, addr = server.accept()
            except OSError:
                return

            threading.Thread(
                target=self.handle,
                args=(conn, addr),
                daemon=True
            ).start()

    def console(self):
        print(HELP)

        while True:
            try:
                line = input("kdc> ")
            except EOFError:
                return

            if not line:
                continue

            command, _, argument = line.partition(" ")
            command = command.lower()

            try:
                if command == "quit":
                    return

                elif command == "keys":
                    with self.lock:
                        for ident, key in self.keys.items():
                            print(
                                f"  {ident}: "
                                f"panjang key {len(key)} karakter"
                            )

                elif command == "setkey":
                    ident, separator, key = argument.partition(" ")

                    if not separator:
                        raise ValueError(
                            "gunakan setkey <id> <key>"
                        )

                    self.set_key(ident, key)
                    print(f"key {ident} diperbarui")

                elif command == "sessionkey" and argument:
                    if argument.lower() == "auto":
                        with self.lock:
                            self.forced_session_key = None

                        print("session key kembali acak")

                    else:
                        check_key(argument)

                        with self.lock:
                            self.forced_session_key = argument

                        print("session key berikutnya dipaksa")

                else:
                    print(HELP)

            except ValueError as error:
                print(f"error: {error}")


def main():
    parser = argparse.ArgumentParser(
        description="Key Distribution Center"
    )

    parser.add_argument(
        "--host",
        default="0.0.0.0"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=5000
    )

    parser.add_argument(
        "--ids",
        default="alice,bob"
    )

    parser.add_argument(
        "--key",
        action="append",
        default=[],
        metavar="ID=KEY"
    )

    args = parser.parse_args()

    kdc = KDC()

    given = dict(
        item.split("=", 1)
        for item in args.key
    )

    for ident in args.ids.split(","):
        while True:
            key = given.get(ident) or input(
                f"master key untuk {ident}: "
            )

            try:
                kdc.set_key(ident, key)
                break

            except ValueError as error:
                print(f"error: {error}")
                given.pop(ident, None)

    server = listen(args.host, args.port)

    print(
        f"KDC aktif di {args.host}:{args.port}"
    )

    threading.Thread(
        target=kdc.serve,
        args=(server,),
        daemon=True
    ).start()

    kdc.console()


if __name__ == "__main__":
    main()