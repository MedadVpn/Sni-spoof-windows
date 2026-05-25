#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Medad SNI Spoofer - Professional SNI Spoofing Tool
Author: Medad Team
License: Open Source (referenced)
"""

import asyncio
import json
import os
import queue
import socket
import struct
import sys
import threading
import time
import traceback
from abc import ABC, abstractmethod
from typing import Dict, Tuple, Optional
import base64
from io import BytesIO

# PyQt6 imports
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QGroupBox, QFormLayout,
    QComboBox, QSpinBox, QMessageBox, QStatusBar, QProgressBar, QTextBrowser,
    QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QByteArray
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QLinearGradient, QBrush, QPixmap, QPainter, QPen
from PyQt6.QtSvg import QSvgRenderer

# WinDivert for packet capture/injection
from pydivert import WinDivert, Packet

# ==================== Network Utilities ====================
def get_default_interface_ipv4(addr="8.8.8.8") -> str:
    """Get the local IPv4 address used to reach the given destination."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
    except OSError:
        return ""
    else:
        return s.getsockname()[0]
    finally:
        s.close()


def get_default_interface_ipv6(addr="2001:4860:4860::8888") -> str:
    """Get the local IPv6 address used to reach the given destination."""
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
    except OSError:
        return ""
    else:
        return s.getsockname()[0]
    finally:
        s.close()


# ==================== TLS Packet Templates ====================
class ClientHelloMaker:
    """Constructs and parses TLS ClientHello packets with SNI and key share."""
    tls_ch_template_str = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    tls_ch_template = bytes.fromhex(tls_ch_template_str)
    template_sni = "mci.ir".encode()
    static1 = tls_ch_template[:11]
    static2 = b"\x20"
    static3 = tls_ch_template[76:120]
    static4 = tls_ch_template[127 + len(template_sni):262 + len(template_sni)]
    static5 = b"\x00\x15"
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_client_hello_with(cls, rnd: bytes, sess_id: bytes, target_sni: bytes,
                              key_share: bytes) -> bytes:
        """Generate a complete ClientHello with given random, session ID, SNI, and key share."""
        server_name_ext = struct.pack("!H", len(target_sni) + 5) + struct.pack("!H",
                                                                               len(target_sni) + 3) + b"\x00" + struct.pack(
            "!H", len(target_sni)) + target_sni
        padding_ext = struct.pack("!H", 219 - len(target_sni)) + (b"\x00" * (219 - len(target_sni)))
        return cls.static1 + rnd + cls.static2 + sess_id + cls.static3 + server_name_ext + cls.static4 + key_share + cls.static5 + padding_ext

    @classmethod
    def parse_client_hello(cls, client_hello_bytes: bytes):
        """Extract random, session ID, SNI, and key share from ClientHello."""
        assert len(client_hello_bytes) == 517
        rnd = client_hello_bytes[11:43]
        sess_id = client_hello_bytes[44:76]
        tls_sni = client_hello_bytes[127:127 + (struct.unpack("!H", client_hello_bytes[125:127])[0])].decode()
        ks_ind = 262 + len(tls_sni)
        key_share = client_hello_bytes[ks_ind:ks_ind + 32]
        assert cls.get_client_hello_with(rnd, sess_id, tls_sni, key_share) == client_hello_bytes
        return rnd, sess_id, tls_sni, key_share

    @classmethod
    def get_client_response_with(cls, app_data1: bytes):
        return cls.tls_change_cipher + cls.tls_app_data_header + struct.pack("!H", len(app_data1)) + app_data1

    @classmethod
    def parse_client_response(cls, client_response_bytes: bytes):
        assert len(client_response_bytes) >= 32
        app_data1 = client_response_bytes[11:]
        assert cls.get_client_response_with(app_data1) == client_response_bytes
        return app_data1


class ServerHelloMaker:
    """Constructs and parses TLS ServerHello packets."""
    tls_sh_template_str = "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e"
    tls_sh_template = bytes.fromhex(tls_sh_template_str)
    static1 = tls_sh_template[:11]
    static2 = b"\x20"
    static3 = tls_sh_template[76:95]
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_server_hello_with(cls, rnd: bytes, sess_id: bytes, key_share: bytes, app_data1: bytes):
        return cls.static1 + rnd + cls.static2 + sess_id + cls.static3 + key_share + cls.tls_change_cipher + cls.tls_app_data_header + struct.pack(
            "!H", len(app_data1)) + app_data1

    @classmethod
    def parse_server_hello(cls, server_hello_bytes: bytes):
        assert len(server_hello_bytes) >= 159
        rnd = server_hello_bytes[11:43]
        sess_id = server_hello_bytes[44:76]
        key_share = server_hello_bytes[95:127]
        app_data1 = server_hello_bytes[138:]
        assert cls.get_server_hello_with(rnd, sess_id, key_share, app_data1) == server_hello_bytes
        return rnd, sess_id, key_share, app_data1


# ==================== Connection Monitoring ====================
class MonitorConnection:
    """Tracks TCP state for a single connection being monitored."""
    def __init__(self, sock: socket.socket, src_ip, dst_ip, src_port, dst_port):
        self.monitor = True
        self.syn_seq = -1
        self.syn_ack_seq = -1
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.id = (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        self.thread_lock = threading.Lock()
        self.sock = sock


class FakeInjectiveConnection(MonitorConnection):
    """Extended monitor connection with fake data injection state."""
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port, fake_data: bytes, peer_sock: socket.socket):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()


# ==================== Packet Injector Base ====================
class TcpInjector(ABC):
    """Abstract base for TCP packet injection."""
    def __init__(self, w_filter: str):
        self.w: WinDivert = WinDivert(w_filter)

    @abstractmethod
    def inject(self, packet: Packet):
        pass

    def run(self):
        with self.w:
            while True:
                packet = self.w.recv(65575)
                self.inject(packet)


class FakeTcpInjector(TcpInjector):
    """Concrete injector that implements the wrong_seq bypass method."""
    def __init__(self, w_filter: str, connections: dict[tuple, FakeInjectiveConnection], log_callback=None):
        super().__init__(w_filter)
        self.connections = connections
        self.log_callback = log_callback
        self.log_callback = None

    def _log(self, msg: str):
        if self.log_callback:
            print(msg)
        else:
            print(msg)

    def fake_send_thread(self, packet: Packet, connection: FakeInjectiveConnection):
        time.sleep(0.001)
        with connection.thread_lock:
            if not connection.monitor:
                return

            packet.tcp.psh = True
            packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
            packet.tcp.payload = connection.fake_data
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff

            # wrong_seq method
            packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
            connection.fake_sent = True
            self.w.send(packet, True)

    def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
        self._log(f"{info_m} {packet}")
        connection.sock.close()
        connection.peer_sock.close()
        connection.monitor = False
        connection.t2a_msg = "unexpected_close"
        connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        self.w.send(packet, False)

    def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent!")
            return
        if packet.tcp.ack and packet.tcp.syn and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected inbound syn-ack packet, seq change! {seq_num} {connection.syn_ack_seq}")
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected inbound syn-ack packet, ack not matched! {ack_num} {connection.syn_seq}")
                return
            connection.syn_ack_seq = seq_num
            self.w.send(packet, False)
            return
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (
                not packet.tcp.fin) and (len(packet.tcp.payload) == 0) and connection.fake_sent:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected inbound ack packet, seq not matched! {seq_num} {connection.syn_ack_seq}")
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected inbound ack packet, ack not matched! {ack_num} {connection.syn_seq}")
                return

            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            return
        self.on_unexpected_packet(packet, connection, "unexpected inbound packet")

    def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.sch_fake_sent:
            self.on_unexpected_packet(packet, connection, "unexpected outbound packet, recv packet after fake sent!")
            return
        if packet.tcp.syn and (not packet.tcp.ack) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if ack_num != 0:
                self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, ack_num is not zero!")
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected outbound syn packet, seq not matched! {seq_num} {connection.syn_seq}")
                return
            connection.syn_seq = seq_num
            self.w.send(packet, False)
            return
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected outbound ack packet, seq not matched! {seq_num} {connection.syn_seq}")
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected outbound ack packet, ack not matched! {ack_num} {connection.syn_ack_seq}")
                return

            self.w.send(packet, False)
            connection.sch_fake_sent = True
            threading.Thread(target=self.fake_send_thread, args=(packet, connection), daemon=True).start()
            return
        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")

    def inject(self, packet: Packet):
        if packet.is_inbound:
            c_id = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
            try:
                connection = self.connections[c_id]
            except KeyError:
                self.w.send(packet, False)
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_inbound_packet(packet, connection)
        elif packet.is_outbound:
            c_id = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
            try:
                connection = self.connections[c_id]
            except KeyError:
                self.w.send(packet, False)
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_outbound_packet(packet, connection)
        else:
            self._log("Impossible packet direction!")


# ==================== Core SNI Spoofing Logic ====================
class SniSpoofCore:
    """Manages the entire SNI spoofing: listening socket, connections, injector thread, asyncio loop."""
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.listen_host = "127.0.0.1"
        self.listen_port = 40443
        self.connect_ip = "104.19.229.21"
        self.connect_port = 443
        self.fake_sni = b"www.hcaptcha.com"
        self.interface_ipv4 = ""

        self.running = False
        self.asyncio_thread: Optional[threading.Thread] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.server_task: Optional[asyncio.Task] = None
        self.injector_thread: Optional[threading.Thread] = None
        self.injector: Optional[FakeTcpInjector] = None
        self.connections: Dict[tuple, FakeInjectiveConnection] = {}
        self.mother_sock: Optional[socket.socket] = None

    def _log(self, msg: str):
        if self.log_callback:
            print(msg)

    def update_config(self, config: dict):
        """Update spoofing parameters (requires restart)."""
        self.listen_host = config.get("LISTEN_HOST", "127.0.0.1")
        self.listen_port = config.get("LISTEN_PORT", 40443)
        self.connect_ip = config.get("CONNECT_IP", "104.19.229.21")
        self.connect_port = config.get("CONNECT_PORT", 443)
        self.fake_sni = config.get("FAKE_SNI", "www.hcaptcha.com").encode()

        # Refresh interface IP
        self.interface_ipv4 = get_default_interface_ipv4(self.connect_ip)

    async def _relay_main_loop(self, sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task, first_prefix_data: bytes):
        """Relay data bidirectionally between two sockets."""
        loop = asyncio.get_running_loop()
        try:
            while True:
                try:
                    data = await loop.sock_recv(sock_1, 65575)
                    if not data:
                        raise ValueError("eof")
                    if first_prefix_data:
                        data = first_prefix_data + data
                        first_prefix_data = b""
                    sent_len = await loop.sock_sendall(sock_2, data)
                    if sent_len != len(data):
                        raise ValueError("incomplete send")
                except Exception:
                    sock_1.close()
                    sock_2.close()
                    peer_task.cancel()
                    return
        except Exception:
            self._log(f"Relay error: {traceback.format_exc()}")

    async def _handle_client(self, incoming_sock: socket.socket, addr):
        """Handle a single incoming connection."""
        try:
            loop = asyncio.get_running_loop()
            # Construct fake TLS ClientHello
            fake_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32), os.urandom(32), self.fake_sni, os.urandom(32)
            )

            # Create outgoing socket
            outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            outgoing_sock.setblocking(False)
            outgoing_sock.bind((self.interface_ipv4, 0))
            outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            src_port = outgoing_sock.getsockname()[1]

            fake_injective_conn = FakeInjectiveConnection(
                outgoing_sock, self.interface_ipv4, self.connect_ip,
                src_port, self.connect_port, fake_data, incoming_sock
            )
            self.connections[fake_injective_conn.id] = fake_injective_conn

            try:
                await loop.sock_connect(outgoing_sock, (self.connect_ip, self.connect_port))
            except Exception as e:
                self._log(f"Connect failed: {e}")
                fake_injective_conn.monitor = False
                del self.connections[fake_injective_conn.id]
                outgoing_sock.close()
                incoming_sock.close()
                return

            # wrong_seq method always
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ValueError("unexpected close")
                elif fake_injective_conn.t2a_msg != "fake_data_ack_recv":
                    raise ValueError(f"unknown t2a msg: {fake_injective_conn.t2a_msg}")
            except Exception as e:
                self._log(f"Fake handshake error: {e}")
                fake_injective_conn.monitor = False
                del self.connections[fake_injective_conn.id]
                outgoing_sock.close()
                incoming_sock.close()
                return

            # Remove from monitoring, start relaying
            fake_injective_conn.monitor = False
            del self.connections[fake_injective_conn.id]

            oti_task = asyncio.create_task(
                self._relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b"")
            )
            await self._relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

        except Exception:
            self._log(f"Handle client error: {traceback.format_exc()}")

    async def _main_async(self):
        """Asynchronous main routine: listen and accept connections."""
        self.mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.mother_sock.setblocking(False)
        self.mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.mother_sock.bind((self.listen_host, self.listen_port))
        self.mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        self.mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        self.mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        self.mother_sock.listen()
        self._log(f"Listening on {self.listen_host}:{self.listen_port}")

        loop = asyncio.get_running_loop()
        while self.running:
            try:
                incoming_sock, addr = await loop.sock_accept(self.mother_sock)
                incoming_sock.setblocking(False)
                incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
                incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
                incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                asyncio.create_task(self._handle_client(incoming_sock, addr))
            except Exception as e:
                if self.running:
                    self._log(f"Accept error: {e}")

    def start(self):
        """Start the SNI spoofing (blocking call, meant to be run in thread)."""
        if self.running:
            self._log("SNI Spoofing already running")
            return

        if not self.interface_ipv4:
            self.interface_ipv4 = get_default_interface_ipv4(self.connect_ip)
            if not self.interface_ipv4:
                self._log("Failed to detect default IPv4 interface")
                return

        self.running = True
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        # Start WinDivert injector in a separate thread
        w_filter = (
            f"tcp and ((ip.SrcAddr == {self.interface_ipv4} and ip.DstAddr == {self.connect_ip}) or "
            f"(ip.SrcAddr == {self.connect_ip} and ip.DstAddr == {self.interface_ipv4}))"
        )
        self.injector = FakeTcpInjector(w_filter, self.connections, self._log)
        self.injector_thread = threading.Thread(target=self.injector.run, daemon=True)
        self.injector_thread.start()
        self._log(f"Injector started with filter: {w_filter}")

        # Run asyncio server
        self.server_task = self.loop.create_task(self._main_async())
        self.loop.run_forever()

    def stop(self):
        """Stop the SNI spoofing gracefully."""
        if not self.running:
            return
        self.running = False
        self._log("Stopping SNI Spoofing...")

        # Close listening socket
        if self.mother_sock:
            self.mother_sock.close()
        # Cancel asyncio tasks
        if self.loop and self.server_task:
            self.loop.call_soon_threadsafe(self.server_task.cancel)
        # Stop WinDivert (will raise StopIteration in injector thread)
        if self.injector and self.injector.w:
            self.injector.w.close()
        # Stop event loop
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)

        # Wait for threads to finish (optional)
        if self.injector_thread and self.injector_thread.is_alive():
            self.injector_thread.join(timeout=2)

        self._log("SNI Spoofing stopped")


# ==================== GUI Application ====================
class LogEmitter(QThread):
    """Thread-safe log signal emitter."""
    log_signal = pyqtSignal(str)

    def emit_log(self, msg: str):
        self.log_signal.emit(msg)


class SniSpoofWorker(QThread):
    """Worker thread that runs the SNI spoofing core."""
    status_signal = pyqtSignal(str)
    log_signal = pyqtSignal(str)

    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self.core = None

    def run(self):
        self.core = SniSpoofCore(log_callback=None)
        self.core.update_config(self.config)
        self.status_signal.emit("started")
        try:
            self.core.start()
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.status_signal.emit("stopped")

    def stop_core(self):
        if self.core:
            self.core.stop()


# ==================== Modern Connect Button ====================
class ModernConnectButton(QPushButton):
    """Custom styled toggle button for connect/disconnect with power icon effect."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedSize(180, 60)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._update_style(False)

    def _update_style(self, checked: bool):
        if checked:
            self.setText("🔌 DISCONNECT")
            self.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #e74c3c, stop:1 #c0392b);
                    color: white;
                    border: none;
                    border-radius: 30px;
                    font-size: 16px;
                    font-weight: bold;
                    padding: 8px 20px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #ff5e4a, stop:1 #d62c1a);
                }
                QPushButton:pressed {
                    background: #a82313;
                }
            """)
        else:
            self.setText("⚡ CONNECT")
            self.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2ecc71, stop:1 #27ae60);
                    color: white;
                    border: none;
                    border-radius: 30px;
                    font-size: 16px;
                    font-weight: bold;
                    padding: 8px 20px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #3be386, stop:1 #2ecc71);
                }
                QPushButton:pressed {
                    background: #1e8a4a;
                }
            """)

    def nextCheckState(self):
        super().nextCheckState()
        self._update_style(self.isChecked())


# ==================== Logo Base64 Data ====================
# Modern professional logo (SVG based) - base64 encoded
LOGO_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAAfQAAAH0CAYAAADL1t+KAAAgAElEQVR4Xuy9B5xc9XU2fKaX7epdQkgUCSSaANFUMcY0AxYYbAM2GNtJ7MQtcYlb8sXEiZ34C3aaSyBuIFEMNqJjAUZCCCEhIdR7Wa202tXW6TPv85xzR/Dm933vCxiMNDorht2duXPn3ud/9z7/55znnH9I/MsRcAQcAUfAEXAEjngEQkf8GfgJOAKOgCPgCDgCjoA4oftF4Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPgCDgCjkANIOCEXgOD6KfgCDgCjoAj4Ag4ofs14Ag4Ao6AI+AI1AACTug1MIh+Co6AI+AIOAKOgBO6XwOOgCPg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wBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBAwQi+Bi2hLMAQMAUPAEDAEjNDtHjAEDAFDwBAwBEoAASP0EriItgRDwBAwBAwBQ8AI3e4BQ8AQMAQMAUOgBBD4/wCT8p7brVebKQAAAABJRU5ErkJggg==
"""

def load_logo_from_base64(size=None):
    """Load QPixmap from base64 image data."""
    # حذف whitespace و خطوط خالی از رشته base64
    cleaned_base64 = LOGO_BASE64.strip()
    # اگر رشته شامل فاصله یا خط جدید بود، پاک کن
    cleaned_base64 = ''.join(cleaned_base64.split())
    
    try:
        image_data = base64.b64decode(cleaned_base64)
        pixmap = QPixmap()
        pixmap.loadFromData(image_data)
        
        if pixmap.isNull():
            print("⚠️ خطا: تصویر بارگذاری نشد - فرمت نامعتبر")
            # بازگشت یک آیکون پیش‌فرض ساده
            pixmap = QPixmap(64, 64)
            pixmap.fill(QColor(74, 111, 165))
            
        if size:
            return pixmap.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        return pixmap
    except Exception as e:
        print(f"⚠️ خطا در بارگذاری لوگو: {e}")
        # آیکون پیش‌فرض
        pixmap = QPixmap(64, 64)
        pixmap.fill(QColor(74, 111, 165))
        if size:
            return pixmap.scaled(size, size)
        return pixmap


# ==================== Main GUI Window ====================
class MedadSniSpoofGUI(QMainWindow):
    """Main GUI window with professional design, modern connect button and embedded logo."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Medad SNI Spoofer")
        self.setMinimumSize(1000, 750)
        self.setStyleSheet(self._get_stylesheet())

        # Load config
        self.config = self._load_config()
        self.worker = None
        self.running = False
        self.log_emitter = LogEmitter()
        self.log_emitter.log_signal.connect(self._append_log)

        # Setup UI
        self._setup_ui()

        # Set application icon
        logo_pixmap = load_logo_from_base64(64)
        self.setWindowIcon(QIcon(logo_pixmap))

        # Timer to update status bar
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._update_status)
        self.status_timer.start(1000)

    def _get_stylesheet(self) -> str:
        """Ultra-modern dark theme with glass morphism."""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0f0c29, stop:0.5 #302b63, stop:1 #24243e);
        }
        QTabWidget::pane {
            border: 1px solid rgba(255,255,255,0.1);
            background: rgba(30,30,50,0.6);
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        QTabBar::tab {
            background: rgba(40,40,60,0.8);
            color: #ccddee;
            padding: 12px 25px;
            margin: 3px;
            border-top-left-radius: 12px;
            border-top-right-radius: 12px;
            font-weight: bold;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4a6fa5, stop:1 #2c3e66);
            color: white;
        }
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4a6fa5, stop:1 #2c3e66);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 10px;
            font-weight: bold;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #5a7fb5, stop:1 #3c4e76);
        }
        QLineEdit, QComboBox, QSpinBox {
            background-color: rgba(20,20,35,0.8);
            color: #ffffff;
            border: 1px solid rgba(74,111,165,0.6);
            border-radius: 8px;
            padding: 8px;
            font-size: 13px;
        }
        QTextEdit, QTextBrowser {
            background-color: rgba(15,15,25,0.9);
            color: #ccddff;
            border: 1px solid rgba(74,111,165,0.5);
            border-radius: 10px;
            font-family: 'Consolas', monospace;
        }
        QGroupBox {
            font-weight: bold;
            border: 1px solid rgba(74,111,165,0.6);
            border-radius: 12px;
            margin-top: 15px;
            padding-top: 15px;
            color: #ddeeff;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 15px;
            padding: 0 8px;
        }
        QLabel {
            color: #eef4ff;
        }
        QStatusBar {
            background-color: rgba(0,0,0,0.5);
            color: #ccddff;
            border-top: 1px solid rgba(74,111,165,0.4);
        }
        """

    def _load_config(self) -> dict:
        """Load configuration from config.json."""
        default_config = {
            "LISTEN_HOST": "127.0.0.1",
            "LISTEN_PORT": 40443,
            "CONNECT_IP": "104.19.229.21",
            "CONNECT_PORT": 443,
            "FAKE_SNI": "www.hcaptcha.com"
        }
        config_path = os.path.join(self._get_exe_dir(), "config.json")
        try:
            with open(config_path, 'r') as f:
                cfg = json.load(f)
                default_config.update(cfg)
        except Exception:
            self._save_config(default_config)
        return default_config

    def _save_config(self, config: dict = None):
        """Save configuration to config.json."""
        if config is None:
            config = self.config
        config_path = os.path.join(self._get_exe_dir(), "config.json")
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            self._append_log(f"Failed to save config: {e}")

    def _get_exe_dir(self) -> str:
        """Get directory of the executable or script."""
        if getattr(sys, 'frozen', False):
            return os.path.dirname(sys.executable)
        else:
            return os.path.dirname(os.path.abspath(__file__))

    def _setup_ui(self):
        """Create all UI components."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Top bar with logo and title
        top_bar = QHBoxLayout()
        
        # Logo در هدر
        logo_label = QLabel()
        logo_pixmap = load_logo_from_base64(48)  # سایز 48x48
        logo_label.setPixmap(logo_pixmap)
        logo_label.setFixedSize(48, 48)
        logo_label.setScaledContents(True)
        logo_label.setStyleSheet("background: transparent;")  # شفاف
        top_bar.addWidget(logo_label)

        title_label = QLabel("MEDAD SNI SPOOFER")
        title_font = QFont("Segoe UI", 24, QFont.Weight.Bold)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #ffffff; margin-left: 10px;")
        top_bar.addWidget(title_label)
        top_bar.addStretch()

        # Version badge
        version_label = QLabel("v1.0 Pro")
        version_label.setStyleSheet("background: rgba(74,111,165,0.3); padding: 4px 12px; border-radius: 20px; color: #aaf;")
        top_bar.addWidget(version_label)
        main_layout.addLayout(top_bar)

        # Tab widget
        self.tab_widget = QTabWidget()
        self.connect_tab = QWidget()
        self.config_tab = QWidget()
        self.about_tab = QWidget()

        self.tab_widget.addTab(self.connect_tab, "  🔗 Connect  ")
        self.tab_widget.addTab(self.config_tab, "  ⚙️ Config  ")
        self.tab_widget.addTab(self.about_tab, "  ℹ️ About  ")

        self._setup_connect_tab()
        self._setup_config_tab()
        self._setup_about_tab()

        main_layout.addWidget(self.tab_widget)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("⚫ Status: Disconnected")
        self.status_bar.addWidget(self.status_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setFixedWidth(120)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def _setup_connect_tab(self):
        layout = QVBoxLayout(self.connect_tab)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Status indicator card
        status_card = QFrame()
        status_card.setStyleSheet("background: rgba(0,0,0,0.3); border-radius: 20px; padding: 15px;")
        status_layout = QVBoxLayout(status_card)
        self.status_indicator = QLabel("🔴 DISCONNECTED")
        self.status_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_indicator.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff6b6b;")
        status_layout.addWidget(self.status_indicator)
        layout.addWidget(status_card)

        # Modern connect button
        self.connect_btn = ModernConnectButton()
        self.connect_btn.clicked.connect(self._toggle)
        btn_container = QHBoxLayout()
        btn_container.addStretch()
        btn_container.addWidget(self.connect_btn)
        btn_container.addStretch()
        layout.addLayout(btn_container)

        # Log area
        log_group = QGroupBox("📋 Live Log")
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        # Info note
        info_label = QLabel("⚠️ Administrator rights required for packet injection.\nTelegram: @Medad_VPN\nSNI Spoofing technique based on patterniha/SNI-Spoofing.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #aaaacc; font-size: 12px; padding: 8px; background: rgba(0,0,0,0.2); border-radius: 10px;")
        layout.addWidget(info_label)

    def _setup_config_tab(self):
        layout = QVBoxLayout(self.config_tab)

        form_widget = QWidget()
        form_layout = QFormLayout(form_widget)
        form_layout.setSpacing(15)

        self.listen_host_edit = QLineEdit(self.config["LISTEN_HOST"])
        self.listen_port_edit = QSpinBox()
        self.listen_port_edit.setRange(1, 65535)
        self.listen_port_edit.setValue(self.config["LISTEN_PORT"])
        self.connect_ip_edit = QLineEdit(self.config["CONNECT_IP"])
        self.connect_port_edit = QSpinBox()
        self.connect_port_edit.setRange(1, 65535)
        self.connect_port_edit.setValue(self.config["CONNECT_PORT"])
        self.fake_sni_edit = QLineEdit(self.config["FAKE_SNI"])

        form_layout.addRow("📡 Listen Host:", self.listen_host_edit)
        form_layout.addRow("🔌 Listen Port:", self.listen_port_edit)
        form_layout.addRow("🌐 Connect IP:", self.connect_ip_edit)
        form_layout.addRow("🔀 Connect Port:", self.connect_port_edit)
        form_layout.addRow("🎭 Fake SNI:", self.fake_sni_edit)

        layout.addWidget(form_widget)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("💾 Save Configuration")
        save_btn.clicked.connect(self._save_config_from_ui)
        refresh_ip_btn = QPushButton("🔄 Refresh Interface IP")
        refresh_ip_btn.clicked.connect(self._refresh_interface_ip)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(refresh_ip_btn)
        layout.addLayout(btn_layout)

        layout.addStretch()
        info_label = QLabel("ℹ️ Changes require restarting the SNI spoofing to take effect.")
        info_label.setStyleSheet("color: #aaaacc;")
        layout.addWidget(info_label)

    def _setup_about_tab(self):
        layout = QVBoxLayout(self.about_tab)

        about_text = QTextBrowser()
        about_text.setOpenExternalLinks(True)
        about_text.setHtml(f"""
        <div style="text-align: center;">
            <img src="data:image/svg+xml;base64,{LOGO_BASE64.strip()}" width="80" height="80">
            <h2 style="color: #4a6fa5;">Medad SNI Spoofer</h2>
            <p>Professional SNI Spoofing Tool.</p>
            <p><b>Version:</b> 1.0.0 Pro</p>
            <p><b>Author:</b> Medad Team</p>
            <p><b>Our Telegram:</b> <a href="https://t.me/medad_Vpn" style="color: #5a7fb5;">Medad Vpn✏️</a></p>
            <br>
            <p><b>Based on:</b> <a href="https://github.com/patterniha/SNI-Spoofing/" style="color: #5a7fb5;">patterniha/SNI-Spoofing</a></p>
            <p><b>License:</b> Open Source (Referenced Repository)</p>
            <hr>
            <p><b>Disclaimer:</b> This tool is for educational purposes only.<br>Use responsibly and in accordance with local laws.</p>
            <p><i>Special thanks to the SNI-Spoofing open source community.</i></p>
        </div>
        """)
        layout.addWidget(about_text)

    def _save_config_from_ui(self):
        self.config["LISTEN_HOST"] = self.listen_host_edit.text()
        self.config["LISTEN_PORT"] = self.listen_port_edit.value()
        self.config["CONNECT_IP"] = self.connect_ip_edit.text()
        self.config["CONNECT_PORT"] = self.connect_port_edit.value()
        self.config["FAKE_SNI"] = self.fake_sni_edit.text()
        self._save_config()
        self._append_log("✅ Configuration saved. Restart SNI spoofing to apply changes.")

    def _refresh_interface_ip(self):
        ip = get_default_interface_ipv4(self.config["CONNECT_IP"])
        if ip:
            QMessageBox.information(self, "Interface IP", f"Detected IPv4: {ip}")
        else:
            QMessageBox.warning(self, "Error", "Could not detect interface IP.")

    def _toggle(self):
        if self.running:
            self._stop()
            self.connect_btn.setChecked(False)
        else:
            self._start()
            self.connect_btn.setChecked(True)

    def _start(self):
        if self.running:
            return
        self.config["LISTEN_HOST"] = self.listen_host_edit.text()
        self.config["LISTEN_PORT"] = self.listen_port_edit.value()
        self.config["CONNECT_IP"] = self.connect_ip_edit.text()
        self.config["CONNECT_PORT"] = self.connect_port_edit.value()
        self.config["FAKE_SNI"] = self.fake_sni_edit.text()
        self._save_config()

        self.worker = SniSpoofWorker(self.config)
        self.worker.status_signal.connect(self._on_status)
        self.worker.log_signal.connect(self._append_log)
        self.worker.start()

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self._append_log("🚀 Starting SNI Spoofing...")

    def _stop(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop_core()
            self.worker.quit()
            self.worker.wait(3000)
        self.running = False
        self.progress_bar.setVisible(False)
        self.status_indicator.setText("🔴 DISCONNECTED")
        self.status_indicator.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff6b6b;")
        self.status_label.setText("⚫ Status: Disconnected")
        self._append_log("🛑 SNI Spoofing stopped.")
        self.connect_btn.setChecked(False)

    def _on_status(self, status: str):
        if status == "started":
            self.running = True
            self.status_indicator.setText("🟢 CONNECTED")
            self.status_indicator.setStyleSheet("font-size: 18px; font-weight: bold; color: #2ecc71;")
            self.status_label.setText("🟢 Status: Connected")
        elif status == "stopped":
            self.running = False
            self.status_indicator.setText("🔴 DISCONNECTED")
            self.status_indicator.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff6b6b;")
            self.status_label.setText("⚫ Status: Disconnected")
            self.progress_bar.setVisible(False)
            self.connect_btn.setChecked(False)

    def _append_log(self, msg: str):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {msg}")
        cursor = self.log_text.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_text.setTextCursor(cursor)

    def _update_status(self):
        if self.running:
            self.status_label.setText("🟢 Status: Connected")
        else:
            self.status_label.setText("⚫ Status: Disconnected")

    def closeEvent(self, event):
        self._stop()
        event.accept()


# ==================== Entry Point ====================
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # تنظیم آیکون برنامه (از لوگو)
    icon_pixmap = load_logo_from_base64(64)
    if not icon_pixmap.isNull():
        app.setWindowIcon(QIcon(icon_pixmap))
    
    window = MedadSniSpoofGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    if sys.platform == "win32":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️ Warning: This application requires Administrator privileges to capture packets.")
    main()
