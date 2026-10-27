import argparse
import secrets
import threading

from aes import check_key, decrypt_text, encrypt_text
from proto import (
    Channel,
    dial,
    listen,
    split_address,
    unpack_fields,
)


HELP = (
    "perintah:\n"
    "  /connect <id_tujuan> <ip[:port]>   mulai sesi\n"
    "  /key <master key baru>             ubah master key\n"
    "  /status                            lihat status sesi\n"
    "  /close                             tutup sesi\n"
    "  /help                              daftar perintah\n"
    "  /quit                              keluar\n"
    "teks biasa dikirim terenkripsi AES ke lawan bicara"
)


class Node:
    def __init__(
        self,
        ident,
        master_key,
        kdc_addr,
        host,
        port
    ):
        self.ident = ident
        self.master_key = master_key
        self.kdc_addr = kdc_addr
        self.host = host
        self.port = port

        self.session = None
        self.occupied = False

        self.lock = threading.Lock()
        self.print_lock = threading.Lock()

    def say(self, text):
        with self.print_lock:
            print(
                f"\r{text}\n> ",
                end="",
                flush=True
            )

    def claim(self):
        with self.lock:
            if self.occupied:
                return False

            self.occupied = True
            return True

    def release(self):
        with self.lock:
            self.occupied = False
            self.session = None

    def open_session(self, channel, session_key, peer):
        session = {
            "channel": channel,
            "key": session_key,
            "peer": peer,
        }

        with self.lock:
            self.session = session

        self.say(
            f"[sesi] aktif dengan {peer}. "
            f"Ks={session_key}. Ketik pesan lalu Enter."
        )

        return session

    def listen_loop(self, server):
        while True:
            try:
                conn, addr = server.accept()
            except OSError:
                return

            threading.Thread(
                target=self.serve_peer,
                args=(conn, addr),
                daemon=True
            ).start()

    def serve_peer(self, conn, addr):
        channel = Channel(conn)

        if not self.claim():
            try:
                channel.send("ERR", "node sedang sibuk")
            except OSError:
                pass

            channel.close()
            return

        try:
            conn.settimeout(15)

            message = channel.recv()

            if (
                not message
                or message[0] != "TKT"
                or len(message) != 2
            ):
                raise ValueError("pesan step 3 tidak valid")

            ticket_plain = decrypt_text(
                self.master_key,
                message[1]
            )

            session_key, peer = unpack_fields(
                ticket_plain,
                2
            )

            check_key(session_key)

            self.say(
                f"[3] dari {addr[0]}: "
                f"ticket E(Kb, Ks||ID_A) = {message[1]}\n"
                f"    dibuka dengan master key -> "
                f"Ks={session_key}, ID_A={peer}"
            )

            nonce = secrets.randbelow(10**9)

            challenge = encrypt_text(
                session_key,
                str(nonce)
            )

            channel.send(
                "CHAL",
                challenge
            )

            self.say(
                f"[4] ke {peer}: "
                f"E(Ks, N2={nonce}) = {challenge}"
            )

            answer = channel.recv()

            if (
                not answer
                or answer[0] != "ANS"
                or len(answer) != 2
            ):
                raise ValueError(
                    "pesan step 5 tidak valid"
                )

            value = int(
                decrypt_text(
                    session_key,
                    answer[1]
                )
            )

            if value != nonce - 1:
                raise ValueError(
                    "verifikasi f(N2) gagal"
                )

            self.say(
                f"[5] dari {peer}: "
                f"E(Ks, f(N2)) = {answer[1]} "
                f"-> f(N2)={value} valid"
            )

            channel.send(
                "READY",
                encrypt_text(session_key, "OK")
            )

            conn.settimeout(None)

        except (OSError, ValueError) as error:
            self.say(
                f"[x] handshake dari {addr[0]} gagal: {error}"
            )

            try:
                channel.send(
                    "ERR",
                    "handshake gagal"
                )
            except OSError:
                pass

            channel.close()
            self.release()
            return

        session = self.open_session(
            channel,
            session_key,
            peer
        )

        self.receive_loop(session)

    def connect(self, peer, ip, port):
        if not self.claim():
            self.say(
                "sudah ada sesi aktif, /close dulu"
            )
            return

        channel = None

        try:
            nonce = str(
                secrets.randbelow(10**9)
            )

            kdc_sock = dial(
                self.kdc_addr[0],
                self.kdc_addr[1],
                self.host
            )

            kdc_channel = Channel(kdc_sock)

            try:
                kdc_channel.send(
                    "REQ",
                    self.ident,
                    peer,
                    nonce
                )

                self.say(
                    f"[1] ke KDC: "
                    f"ID_A={self.ident} "
                    f"ID_B={peer} "
                    f"N1={nonce}"
                )

                reply = kdc_channel.recv()

            finally:
                kdc_channel.close()

            if not reply:
                raise ValueError(
                    "KDC tidak membalas"
                )

            if reply[0] == "ERR":
                raise ValueError(
                    f"KDC menolak: {reply[1]}"
                )

            if (
                reply[0] != "RESP"
                or len(reply) != 3
            ):
                raise ValueError(
                    "balasan KDC tidak valid"
                )

            plain = decrypt_text(
                self.master_key,
                reply[1]
            )

            session_key, id_a, id_b, nonce_back = unpack_fields(
                plain,
                4
            )

            ticket = reply[2]

            if (
                id_a != self.ident
                or id_b != peer
                or nonce_back != nonce
            ):
                raise ValueError(
                    "ID_A, ID_B, atau N1 "
                    "pada balasan KDC tidak cocok"
                )

            check_key(session_key)

            self.say(
                f"[2] dari KDC: {reply[1]}\n"
                f"    dibuka dengan master key -> "
                f"Ks={session_key}, "
                f"ID_A/ID_B/N1 cocok"
            )

            peer_sock = dial(
                ip,
                port,
                self.host
            )

            channel = Channel(peer_sock)

            channel.send(
                "TKT",
                ticket
            )

            self.say(
                f"[3] ke {peer}: ticket {ticket}"
            )

            challenge = channel.recv()

            if (
                not challenge
                or challenge[0] != "CHAL"
                or len(challenge) != 2
            ):
                detail = (
                    challenge[1]
                    if challenge and len(challenge) > 1
                    else "tidak ada balasan"
                )

                raise ValueError(
                    f"step 4 gagal: {detail}"
                )

            nonce_peer = int(
                decrypt_text(
                    session_key,
                    challenge[1]
                )
            )

            self.say(
                f"[4] dari {peer}: "
                f"E(Ks, N2) = {challenge[1]} "
                f"-> N2={nonce_peer}"
            )

            answer = encrypt_text(
                session_key,
                str(nonce_peer - 1)
            )

            channel.send(
                "ANS",
                answer
            )

            self.say(
                f"[5] ke {peer}: "
                f"E(Ks, f(N2)={nonce_peer - 1}) = {answer}"
            )

            # Tunggu hasil verifikasi langkah 5 dari responder.
            ready = channel.recv()

            if (
                not ready
                or ready[0] != "READY"
                or len(ready) != 2
            ):
                raise ValueError(
                    "responder belum mengonfirmasi "
                    "verifikasi langkah 5"
                )

            if decrypt_text(session_key, ready[1]) != "OK":
                raise ValueError(
                    "konfirmasi langkah 5 tidak valid"
                )

            peer_sock.settimeout(None)

        except (OSError, ValueError) as error:
            self.say(
                f"[x] gagal: {error}"
            )

            if channel:
                channel.close()

            self.release()
            return

        session = self.open_session(
            channel,
            session_key,
            peer
        )

        threading.Thread(
            target=self.receive_loop,
            args=(session,),
            daemon=True
        ).start()

    def receive_loop(self, session):
        channel = session["channel"]

        try:
            while True:
                message = channel.recv()

                if message is None or message[0] == "BYE":
                    break

                if message[0] == "ERR":
                    self.say(
                        f"[sesi] lawan melaporkan error: "
                        f"{message[1:]}"
                    )
                    break

                if message[0] == "MSG" and len(message) == 2:
                    try:
                        plain = decrypt_text(
                            session["key"],
                            message[1]
                        )

                    except ValueError as error:
                        self.say(
                            f"[{session['peer']}] "
                            f"gagal dekripsi: {error}"
                        )
                        continue

                    self.say(
                        f"[{session['peer']}] {plain}\n"
                        f"    cipher(hex): {message[1]}"
                    )

        except (OSError, ValueError) as error:
            self.say(
                f"[sesi] koneksi berakhir: {error}"
            )

        finally:
            self.end_session(session)

    def end_session(self, session):
        with self.lock:
            current = self.session is session

            if current:
                self.session = None
                self.occupied = False

        session["channel"].close()

        if current:
            self.say(
                f"[sesi] dengan {session['peer']} berakhir"
            )

    def send_message(self, text):
        with self.lock:
            session = self.session

        if session is None:
            self.say(
                "belum ada sesi. "
                "gunakan /connect atau tunggu lawan terhubung"
            )
            return

        try:
            cipher = encrypt_text(
                session["key"],
                text
            )

            session["channel"].send(
                "MSG",
                cipher
            )

        except ValueError:
            self.say(
                "pesan harus berupa karakter ASCII"
            )
            return

        except OSError as error:
            self.say(
                f"gagal mengirim: {error}"
            )
            return

        self.say(
            f"[kamu] {text}\n"
            f"    cipher(hex): {cipher}"
        )

    def close_session(self):
        with self.lock:
            session = self.session

        if session is None:
            self.say(
                "tidak ada sesi aktif"
            )
            return

        try:
            session["channel"].send("BYE")
        except OSError:
            pass

        self.end_session(session)

    def status(self):
        with self.lock:
            session = self.session

        if session is None:
            self.say(
                f"ID={self.ident} | "
                f"master key {len(self.master_key)} karakter | "
                f"tidak ada sesi"
            )

        else:
            self.say(
                f"ID={self.ident} | "
                f"master key {len(self.master_key)} karakter | "
                f"sesi dengan {session['peer']} | "
                f"Ks={session['key']}"
            )

    def run(self):
        print(HELP)
        print("> ", end="", flush=True)

        while True:
            try:
                line = input()
            except EOFError:
                break

            if not line:
                print("> ", end="", flush=True)
                continue

            if not line.startswith("/"):
                self.send_message(line)
                continue

            parts = line.split(maxsplit=2)
            command = parts[0].lower()

            if command == "/quit":
                break

            elif command == "/help":
                self.say(HELP)

            elif command == "/status":
                self.status()

            elif command == "/close":
                self.close_session()

            elif (
                command == "/key"
                and len(line.split(maxsplit=1)) == 2
            ):
                new_key = line.partition(" ")[2]

                try:
                    check_key(new_key)

                except ValueError as error:
                    self.say(
                        f"key ditolak: {error}"
                    )
                    continue

                self.master_key = new_key

                self.say(
                    "master key diubah "
                    "(samakan dengan setkey di KDC)"
                )

            elif command == "/connect" and len(parts) == 3:
                try:
                    ip, port = split_address(
                        parts[2],
                        self.port
                    )

                except ValueError:
                    self.say(
                        "format alamat salah, "
                        "contoh: 192.168.1.20:6000"
                    )
                    continue

                threading.Thread(
                    target=self.connect,
                    args=(parts[1], ip, port),
                    daemon=True
                ).start()

            else:
                self.say(HELP)

        self.close_session_quiet()

    def close_session_quiet(self):
        with self.lock:
            session = self.session

        if session:
            try:
                session["channel"].send("BYE")
            except OSError:
                pass

            session["channel"].close()


def main():
    parser = argparse.ArgumentParser(
        description="Node Alice/Bob"
    )

    parser.add_argument(
        "--id",
        required=True
    )

    parser.add_argument(
        "--kdc",
        required=True,
        help="ip[:port] KDC"
    )

    parser.add_argument(
        "--host",
        default="0.0.0.0"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=6000
    )

    parser.add_argument(
        "--key"
    )

    args = parser.parse_args()

    master_key = args.key

    while True:
        if master_key is None:
            master_key = input(
                f"master key {args.id} "
                "(16/24/32 karakter ASCII): "
            )

        try:
            check_key(master_key)
            break

        except ValueError as error:
            print(f"error: {error}")
            master_key = None

    node = Node(
        args.id,
        master_key,
        split_address(args.kdc, 5000),
        args.host,
        args.port
    )

    server = listen(
        args.host,
        args.port
    )

    print(
        f"{args.id} mendengarkan di "
        f"{args.host}:{args.port}"
    )

    threading.Thread(
        target=node.listen_loop,
        args=(server,),
        daemon=True
    ).start()

    node.run()


if __name__ == "__main__":
    main()