"""DNS Authenticator using UDP sockets and the libnetfilter_queue library to intercept and answer DNS challenges."""

import abc
import logging
import os
import queue
import socket
import threading
from typing import Any, Callable, Optional

import dns
import dns.message
import dns.resolver
from certbot import errors
from certbot.plugins import dns_common
# from IPython import embed

from .dnsutils import dns_challenge_server_ips

NETFILTER_SUPPORTED = True
try:
    import iptc
    from netfilterqueue import NetfilterQueue
    from scapy.layers.inet import IP, UDP
    from scapy.layers.inet6 import IPv6
except ImportError:
    NETFILTER_SUPPORTED = False

SOL_IPV6 = 41
IPV6_HDRINCL = 36

logger = logging.getLogger(__name__)

NETFILTER_MAX_QUEUES = 64


class ProcolAgnosticNfqueue:
    def __init__(self, version: int) -> None:
        self.nfqueue = NetfilterQueue()
        self.queue_num: int = 0
        if version == 4:
            self.table = iptc.Table
            self.rule = iptc.Rule
        elif version == 6:
            self.table = iptc.Table6
            self.rule = iptc.Rule6
        self.rule_inserted = False
        self.bound = False

    def bind(self, func) -> bool:
        for i in range(0, NETFILTER_MAX_QUEUES):
            try:
                self.nfqueue.bind(i, func)
                self.queue_num = i
                self.bound = True
                return True
            except OSError:
                pass
        return False

    def run(self, block: bool = True) -> None:
        self.nfqueue.run(block)

    def unbind(self) -> None:
        if self.bound:
            try:
                os.close(self.nfqueue.get_fd())
            except:
                pass
            try:
                self.nfqueue.unbind()
            finally:
                self.bound = False

    def _modify_rule(self, delete: bool) -> None:
        chain = iptc.Chain(self.table(self.table.FILTER), "INPUT")
        rule = self.rule()
        rule.protocol = "udp"
        match = iptc.Match(rule, "udp")
        match.dport = "53"
        target = iptc.Target(rule, "NFQUEUE")
        target.set_parameter("queue-num", str(self.queue_num))
        target.set_parameter("queue-bypass")
        rule.target = target
        rule.add_match(match)
        if delete:
            chain.delete_rule(rule)
        else:
            chain.insert_rule(rule)

    def insert_rule(self) -> None:
        if not self.rule_inserted:
            self._modify_rule(False)
            self.rule_inserted = True

    def delete_rule(self) -> None:
        if self.rule_inserted:
            try:
                self._modify_rule(True)
            finally:
                self.rule_inserted = False


class DNSAuthenticator(abc.ABC):
    def __init__(self) -> None:
        self.validations: dict[str, list[str]] = {}
        self.lock = threading.Lock()

    def add_challenge(self, validation_name: str, validation: str) -> None:
        key = validation_name.rstrip(".").lower()

        with self.lock:
            self.validations.setdefault(key, []).append(validation)

    def _reply_from_data(self, data: bytes) -> Optional[bytes]:
        try:
            request = dns.message.from_wire(data)

            # We only handle standard queries with at least one question
            if not request.question:
                return None

            q = request.question[0]

            if q.rdclass != dns.rdataclass.IN or q.rdtype != dns.rdatatype.TXT:
                return None

            # Normalize name
            qname_str = q.name.to_text(omit_final_dot=True).lower()

            with self.lock:
                txt_values = self.validations.get(qname_str)

            if not txt_values:
                return None

            # Build response
            response = dns.message.make_response(request)
            response.flags |= (
                dns.flags.AA | dns.flags.RA
            )  # authoritative + recursion available

            rrset = dns.rrset.RRset(q.name, dns.rdataclass.IN, dns.rdatatype.TXT)
            for txt in txt_values:
                rrset.add(
                    dns.rdata.from_text(
                        dns.rdataclass.IN, dns.rdatatype.TXT, f'"{txt}"'
                    )
                )

            response.answer.append(rrset)
            return response.to_wire()

        except Exception:
            return None

    @abc.abstractmethod
    def start(self):
        pass

    def stop(self):
        self.validations.clear()


def _send_raw_udp_packet(src_addr, dst_addr, src_port, dst_port, payload, ip_layer):
    s = socket.socket(
        socket.AF_INET if ip_layer == IP else socket.AF_INET6,
        socket.SOCK_RAW,
        socket.IPPROTO_UDP,
    )
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if ip_layer == IPv6:
        s.setsockopt(SOL_IPV6, IPV6_HDRINCL, True)
        dst = (dst_addr, 0, 0, 0)
    else:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)
        dst = (dst_addr, dst_port)
    s.sendto(
        bytes(
            ip_layer(src=src_addr, dst=dst_addr)
            / UDP(sport=src_port, dport=dst_port)
            / payload
        ),
        dst,
    )
    s.close()


class NetfilterAuthenticator(DNSAuthenticator):
    def __init__(self) -> None:
        super().__init__()
        self.nfqueue4 = ProcolAgnosticNfqueue(4)
        self.nfqueue6 = ProcolAgnosticNfqueue(6)
        self.threads: list[threading.Thread] = []

    def _start_nfqueue_thread(self, nfq: ProcolAgnosticNfqueue, handler) -> None:
        # Bind queue and insert rule
        if not nfq.bind(handler):
            raise RuntimeError("Failed to bind a netfilter queue (all queues busy?)")
        nfq.insert_rule()

        # Run nfqueue in a daemon thread
        t = threading.Thread(target=self._nfqueue_loop, args=(nfq,), daemon=True)
        t.start()
        self.threads.append(t)

    def _nfqueue_loop(self, nfq: ProcolAgnosticNfqueue) -> None:
        try:
            # netfilterqueue.run() blocks; we stop by calling unbind() in stop()
            nfq.run(block=True)
        except Exception:
            # On unbind/cleanup, nfqueue.run() may raise; that's fine.
            pass

    def start(self):
        self._start_nfqueue_thread(self.nfqueue4, self._handle_packet4)
        self._start_nfqueue_thread(self.nfqueue6, self._handle_packet6)

    def _handle_packet4(self, packet) -> None:
        self._handle_packet_helper(packet, IP)

    def _handle_packet6(self, packet) -> None:
        self._handle_packet_helper(packet, IPv6)

    def _handle_packet_helper(self, packet, ip_layer):
        try:
            pkt = ip_layer(packet.get_payload())
        except Exception:
            packet.accept()
            return

        # Expect IP/UDP/DNS; the iptables rule already matched udp dport 53,
        # but we still validate quickly to be safe.
        layers = pkt.layers()
        if len(layers) < 2 or UDP not in layers:
            packet.accept()
            return

        udp = pkt.getlayer(UDP)
        reply = self._reply_from_data(bytes(udp.payload))
        if reply is None:
            # Not our TXT or unsupported type — let normal stack handle it
            packet.accept()
            return

        # We’ll answer ourselves; drop original
        packet.drop()
        try:
            _send_raw_udp_packet(
                pkt.dst, pkt.src, udp.dport, udp.sport, reply, ip_layer
            )
        except Exception:
            pass

    def stop(self):
        try:
            self.nfqueue4.delete_rule()
        except iptc.IPTCError:
            pass

        try:
            self.nfqueue6.delete_rule()
        except iptc.IPTCError:
            pass

        try:
            self.nfqueue4.unbind()
        except Exception:
            pass

        try:
            self.nfqueue6.unbind()
        except Exception:
            pass

        # Join worker threads briefly
        for t in self.threads:
            t.join(timeout=1.0)
        self.threads.clear()

        super().stop()


class ServerAuthenticator(DNSAuthenticator):
    def __init__(self, port: int = 53, num_workers: int = 5) -> None:
        super().__init__()
        self.port = port
        self.num_workers = num_workers
        self.socket: Optional[socket.socket] = None

        self.stop_event = threading.Event()
        self.listener_thread: Optional[threading.Thread] = None
        self.worker_threads: list[threading.Thread] = []
        self.queue: queue.Queue[tuple[bytes, tuple[str, int]]] = queue.Queue()

    def try_bind(self, ip: str) -> bool:
        if self.socket:
            return True

        s = None
        try:
            if ":" in ip:
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except OSError:
                    pass
                s.bind((ip, self.port, 0, 0))
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except OSError:
                    pass
                s.bind((ip, self.port))
            self.socket = s
            return True
        except OSError:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
            return False

    def start(self) -> None:
        self.stop_event.clear()

        # Start listener
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()

        # Start worker threads
        for _ in range(self.num_workers):
            thread = threading.Thread(target=self._worker, daemon=True)
            thread.start()
            self.worker_threads.append(thread)

    def _listen(self) -> None:
        if self.socket is None:
            raise RuntimeError("Socket not connected.")

        while not self.stop_event.is_set():
            try:
                embed()
                data, addr = self.socket.recvfrom(0xFFFF)
                self.queue.put((data, addr))
            except Exception:
                continue

    def _worker(self) -> None:
        if self.socket is None:
            raise RuntimeError("Socket not connected.")

        while not self.stop_event.is_set():
            try:
                data, addr = self.queue.get(timeout=0.5)
                reply = self._reply_from_data(data)
                if reply:
                    self.socket.sendto(reply, addr)
            except queue.Empty:
                continue
            except Exception:
                continue

    def stop(self) -> None:
        self.stop_event.set()

        if self.listener_thread:
            self.listener_thread.join(timeout=1.0)

        for t in self.worker_threads:
            t.join(timeout=1.0)

        if self.socket:
            self.socket.close()
            self.socket = None

        self.worker_threads.clear()
        self.queue.queue.clear()

        super().stop()


class Authenticator(dns_common.DNSAuthenticator):
    description = (
        "Obtain certificates using a DNS TXT record (by configuring the NS record of "
        "_acme-challenge.yourdomain.com to point to the server which is running certbot)"
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[dns_common.CredentialsConfiguration] = None
        self.authenticator: Optional[DNSAuthenticator] = None
        self.authenticator_started: bool = False

        self.listen_port: int = self.conf("port")
        self.bind_addresses: list[str] = list(dict.fromkeys(self.conf("bind-address")))
        self.mode: str = self.conf("mode")
        self.workers: int = max(
            1,
            self.conf(
                "workers",
            ),
        )

    @classmethod
    def add_parser_arguments(
        cls, add: Callable[..., None], default_propagation_seconds: int = 0
    ) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add(
            "port",
            type=int,
            default=53,
            help=(
                "Port to run the local DNS server on (default: 53). "
                "Requires root privileges for ports <1024."
            ),
        )

        add(
            "bind-address",
            nargs="+",
            default=[],
            metavar="IP",
            help=(
                "IP address(es) to bind the DNS server to. Can be specified multiple times. "
                "If omitted, plugin will try domain-specific IPs, then 0.0.0.0 and ::."
            ),
        )

        add(
            "mode",
            choices=("auto", "bind-only", "nf-only"),
            default="auto",
            help=(
                "Challenge interception mode: "
                "'auto' (try bind then fallback to netfilter), "
                "'bind-only' (never use netfilter), "
                "'nf-only' (only use netfilter). Default: auto."
            ),
        )

        add(
            "workers",
            type=int,
            default=5,
            help="Number of worker threads for handling DNS queries.",
        )

    def more_info(self) -> str:
        return "This plugin intercepts DNS TXT queries to respond to a dns-01 challenge"

    def _setup_credentials(self) -> None:
        pass

    def _build_candidates(self, domain: str) -> list[str]:
        if self.bind_addresses:
            return self.bind_addresses

        addresses = dns_challenge_server_ips(domain)
        addresses.extend(("0.0.0.0", "::"))
        return list(dict.fromkeys(addresses))

    def _make_authenticator(self, domain: str) -> DNSAuthenticator:
        if self.mode == "nf-only":
            if NETFILTER_SUPPORTED:
                return NetfilterAuthenticator()

            raise errors.PluginError("netfilter is unavailable.")

        # if self.mode in ("auto", "bind-only"):
        candidates = self._build_candidates(domain)
        server = ServerAuthenticator(port=self.listen_port, num_workers=self.workers)
        for ip in candidates:
            if server.try_bind(ip):
                logger.debug("Started DNS server on %s:%d", ip, self.listen_port)
                return server

        if self.mode == "bind-only":
            raise errors.PluginError(
                f"Could not bind UDP/{self.listen_port} on: {', '.join(candidates)}."
            )

        # Fallback to Netfilter if bind failed everywhere
        if not NETFILTER_SUPPORTED:
            raise errors.PluginError(
                f"Could not bind UDP/53 on: {', '.join(candidates)} and netfilter is unavailable."
            )

        logger.debug("Falling back to NetFilter Authenticator")
        return NetfilterAuthenticator()

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        if self.authenticator is None:
            self.authenticator = self._make_authenticator(domain)

        self.authenticator.add_challenge(validation_name, validation)
        if not self.authenticator_started:
            self.authenticator.start()
            self.authenticator_started = True

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        if self.authenticator:
            self.authenticator.stop()
            self.authenticator = None
            self.authenticator_started = False
