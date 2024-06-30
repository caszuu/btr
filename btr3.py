#!/usr/bin/env python3

import argparse
import selectors
import traceback
import socket
import os

if os.name == 'nt':
    # enable ansi colors in windows cmd
    import ctypes

    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        pass # in the case cmd doesn't support ansi colors (pre win10)

bold_escape = "\033[1m"
reset_escape = "\033[0m"

error_escape = "\033[31m"
warn_escape = "\033[33m"

# initiates a btr tcp tunnel daemon (with no special connect methods)
def open_tunnel(args: argparse.Namespace) -> socket.socket:
    if not args.proxy_addr:
        print(f"{error_escape}error{reset_escape}: no http proxy specified")
        exit(-1)
    
    # create a proxied socket

    proxy_addr = args.proxy_addr.split(':', 2)
    if len(proxy_addr) == 1:
        proxy_addr = (proxy_addr[0], 3128) 

    relay_addr = args.relay_addr
    if ':' in relay_addr:
       relay_addr = relay_addr.split(':', 2)[0]

    tunnel_ports = args.tcp_tunnel.split(':', 2)
    if len(tunnel_ports) == 1:
        tunnel_ports = (tunnel_ports[0], tunnel_ports[0])

    if args.verbose:
        print(f"{bold_escape}verbose{reset_escape}: initiating proxied relay connection...")
        print(f"{bold_escape}verbose{reset_escape}: proxy: {proxy_addr} relay: {relay_addr}:{tunnel_ports[1]}")

    sock = socket.create_connection(proxy_addr)
    sock.send(bytes(f"CONNECT {relay_addr}:{tunnel_ports[1]} HTTP/1.1\r\n\r\n", 'utf-8'))

    response = sock.recv(32768)
    if not response.startswith(bytes("HTTP/1.1 200", 'utf-8')):
        code = str(response, 'utf-8').split('\n', 2)[0]
        print(f"{error_escape}error{reset_escape}: failed to create a tcp connection through proxy: {code}")

        if args.verbose:
            print(f"full response: {str(response, 'utf-8')}")

        exit(-1)
    
    return sock

# creates a direct tcp connection, only for testing
def direct_tunnel(args: argparse.Namespace) -> socket.socket:
    relay_addr = args.relay_addr
    if ':' in relay_addr:
       relay_addr = relay_addr.split(':', 2)[0]

    tunnel_ports = args.tcp_tunnel.split(':', 2)
    if len(tunnel_ports) == 1:
        tunnel_ports = (tunnel_ports[0], tunnel_ports[0])

    return socket.create_connection((relay_addr, int(tunnel_ports[1])))

# btr python-native tcp tunnel daemon
def btr_socket_daemon(create_new_conn, args: argparse.Namespace):
    if not args.relay_addr:
        print(f"{error_escape}error{reset_escape}: no relay addr specified")
        exit(-1)

    if not args.tcp_tunnel:
        print(f"{error_escape}error{reset_escape}: no ports specified for the tunnel")
        exit(-1)

    relay_addr = args.relay_addr
    if ':' in relay_addr:
       print(f"{warn_escape}warn:{reset_escape} detected port number in relay address, ingnoring, please specify ports using the -t argument") 
       relay_addr = relay_addr.split(':', 2)[0]

    tunnel_ports = args.tcp_tunnel.split(':', 2)
    if len(tunnel_ports) == 1:
        tunnel_ports = (tunnel_ports[0], tunnel_ports[0])

    local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # local_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    local_sock.bind(('', int(tunnel_ports[0])))
    local_sock.listen(100)
    local_sock.setblocking(False)

    print(f"[{tunnel_ports[0]} -> {tunnel_ports[1]}] {bold_escape}info{reset_escape}: starting btr tcp tunnel...")
    if args.verbose:
        print(f"[{tunnel_ports[0]} -> {tunnel_ports[1]}] {bold_escape}verbose{reset_escape}: local_addr: {local_sock.getsockname()} remove_addr: {relay_addr}")
    
    # start the daemon

    sel = selectors.DefaultSelector()

    idle_work_socks = []

    def read_work_conn(rsock, wsock):
        data = rsock.recv(32768)

        if data:
            wsock.send(data)
        else:
            sel.unregister(rsock)
            
            if rsock.getsockname()[1] == int(tunnel_ports[0]):
                # local sock
                print(f"[{tunnel_ports[0]} -> {tunnel_ports[1]}] {bold_escape}info{reset_escape}: closing work conn from {rsock.getpeername()}")
            else:
                # work sock
                if args.enable_reuse and len(idle_work_socks) < args.pool_size:
                    if args.verbose:
                        print(f"[{tunnel_ports[0]} -> {tunnel_ports[1]}] {bold_escape}verbose{reset_escape}: trying to reuse a closing work conn and pool it")

                    rsock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    idle_work_socks.append(rsock)
                    return

            rsock.close()
    
    def accept_work_conn(sock, _):
        sock, addr = sock.accept()
        sock.setblocking(False)

        if not len(idle_work_socks) == 0:
            work_sock = idle_work_socks.pop()
        else:
            try:
                work_sock = create_new_conn(args)
                work_sock.setblocking(False)
            except ConnectionError:
                sock.close()
                return

        print(f"[{tunnel_ports[0]} -> {tunnel_ports[1]}] {bold_escape}info{reset_escape}: accepting new work conn from {addr}")

        sel.register(sock, selectors.EVENT_READ, (read_work_conn, work_sock))
        sel.register(work_sock, selectors.EVENT_READ, (read_work_conn, sock))

    sel.register(local_sock, selectors.EVENT_READ, (accept_work_conn, None))

    if not args.pool_size == 0:
        print(f"[{tunnel_ports[0]} -> {tunnel_ports[1]}] {bold_escape}info{reset_escape}: creating {args.pool_size} idle work conns...")

    for i in range(args.pool_size):
        # open pooled idle connections

        rsock = create_new_conn(args)
        rsock.setblocking(False)
        rsock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        idle_work_socks.append(rsock)

    try:
        while True:
            try:
                events = sel.select()
                for key, mask in events:
                    callback = key.data[0]
                    callback(key.fileobj, key.data[1])
            except Exception:
                print(f"[{tunnel_ports[0]} -> {tunnel_ports[1]}] {warn_escape}warning{reset_escape}: exception occured in btr tunnel daemon, trying to continue...")

                print("------------------------")
                print(traceback.format_exc(), end="")
                print("------------------------")
    except KeyboardInterrupt:
        print(f"[{tunnel_ports[0]} -> {tunnel_ports[1]}] {bold_escape}info{reset_escape}: stopping btr tunnel daemon...")
        local_sock.close()

# == btr dio ==

import dataclasses
import threading
import time
import select

# dio fragment ordering algo: receive and order frag packets until all received
# if all frags arrived by the time all packet arrives, packet is sent, if not, packet is considered lost (no wait)

# TODO: tcp-over-quic integration 

@dataclasses.dataclass(kw_only=True)
class DioLink:
    out_sock: socket.socket = dataclasses.field(init=False)
    out_addr: tuple[str, int] = dataclasses.field(default_factory=tuple)

    lazy_addr: tuple[str, int] | None = None
    down_buffer: list[bytes] = dataclasses.field(default_factory=list) # buffered downstream packets

    # down remaining frag buf
    down_link_mtu: int
    down_frag_buf: bytes = dataclasses.field(default_factory=bytes)
    down_frag_index: int = 0

    # up frag assembly buf
    up_link_mtu: int
    up_frag_buf: dict[int, bytes] = dataclasses.field(default_factory=dict) # int is frag_index

    latest_time: float # timestamp for link time out

# a layered quic conn which is transparently being transfered over a dio link
@dataclasses.dataclass(kw_only=True)
class QuicStream:
    out_sock: socket.socket = dataclasses.field(init=False)
    out_addr: tuple[str, int] = dataclasses.field(default_factory=tuple) # link.out_addr = quic_server_sock
    is_localy_closed: bool = False

dio_up_trans = 0 # rebind with link id 0 and (rb magic header) otherwise extra byte in dio header for frag_byte
dio_up_hearthbeat = 1 # ping with link id 0

dio_down_trans = 0 # rebind ok on link id 0 (with rb header) and ping with (ping header) otherwise extra byte in dio header for frag_byte
dio_down_buf = 1 # alias with down_trans but must be the last frag packet and signals that more outbound packets are buffered with no lazy addr (heartbeat required)

dio_frag_all = 0x80 # 128
dio_frag_mask = 0x7F # 127 == bitwise not 128

conf_dio_link_timeout = 60
conf_dio_heartbeat_time = 5

def pack_dio(dio_enum: int, dio_link: int, data: bytes) -> bytes:
    # print((dio_link << 2 | dio_enum), dio_enum, dio_link)
    return b''.join((b"BD", (dio_link << 2 | dio_enum).to_bytes(1, 'little', signed=False), data))

def pack_dio_frag(dio_enum: int, dio_link: int, frag_index: int, frag_fin: bool, data: bytes) -> bytes:
    # print((dio_link << 2 | dio_enum), dio_enum, dio_link)
    return b''.join((b"BD", (dio_link << 2 | dio_enum).to_bytes(1, 'little', signed=False), (frag_fin << 7 | frag_index).to_bytes(1, 'little', signed=False), data))

def btr_dio_serve(args: argparse.Namespace):
    try:
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.connection import QuicConnection
        from aioquic.quic.events import StreamDataReceived, StopSendingReceived, StreamReset
    except ImportError:
        print(f"{error_escape}error{reset_escape}: failed to import aioquic module which is required by btr dio")
        exit(-1)
    
    if not args.relay_addr:
        print(f"{error_escape}error{reset_escape}: no relay addr specified to bind server to")
        exit(-1)
    
    if not args.quic_cert:
        print(f"{error_escape}error{reset_escape}: no certificates specified which are required by btr dio")
        exit(-1)
    
    if not args.quic_priv:
        print(f"{error_escape}error{reset_escape}: no private key specified which are required by btr dio")
        exit(-1)

    # if not args.quic_passwd:
    #     print(f"{error_escape}error{reset_escape}: no certificates specified which are required by btr dio")
    #     exit(-1)

    server_addr, server_port = args.relay_addr.split(':', 2)

    print(f"{bold_escape}info{reset_escape}: starting btr dio server on {server_addr}:{server_port}...")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((server_addr, int(server_port)))

    active_links: dict[int, DioLink] = {}
    outbound_selector = selectors.DefaultSelector()
    
    # == dio fragmentation ==

    # takes and tries to assemble a full packet from dio frag packets
    def assemble_up_frag(data: bytes, link: DioLink, frag_byte: int) -> None:
        if frag_byte & dio_frag_all:
            if len(link.up_frag_buf) == (dio_frag_mask & frag_byte):
                # frag packet complete, send

                link.up_frag_buf[dio_frag_mask & frag_byte] = data
                link.out_sock.sendto(b''.join(link.up_frag_buf.values()), link.out_addr)
            else:
                pass # frag packet incomplete, consider lost
            
            link.up_frag_buf = {}
        else:
            # frag packet, append to frag_buf

            link.up_frag_buf[frag_byte] = data

    # continues sending frag packets if there's a frag packet on progress
    def continue_frag_stream(dio_enum: int, addr: tuple[str, int], link_id: int, link: DioLink) -> bool:
        if len(link.down_frag_buf) == 0:
            return False

        link.latest_time = time.time()
        
        if len(link.down_frag_buf) <= link.down_link_mtu:
            frag = link.down_frag_buf
            frag_index = link.down_frag_index
            frag_fin = True

            link.down_frag_buf = b""
            link.down_frag_index = 0
        else:
            frag = link.down_frag_buf[:link.down_link_mtu]
            frag_index = link.down_frag_index
            frag_fin = False

            link.down_frag_buf = link.down_frag_buf[link.down_link_mtu:]
            link.down_frag_index += 1

        server_sock.sendto(pack_dio_frag(dio_enum, link_id, frag_index, frag_fin, frag), addr)
        return True

    # helper that takes care of starting fragmentation if nessesary, only run when no frag transfer in progress
    def initial_down_stream_transfer(dio_enum: int, addr: tuple[str, int], link_id: int, link: DioLink, data: bytes) -> None:
        if len(data) > 127 * link.down_link_mtu:
            if args.verbose:
                print(f"{warn_escape}warn{reset_escape}: packet exceeded maximum allowed mtu of {127 * link.down_link_mtu} bytes, ignoring...")
            return

        is_frag = len(data) > link.down_link_mtu

        if is_frag:
            link.down_frag_index += 1
            link.down_frag_buf = data[link.down_link_mtu:]
            data = data[:link.down_link_mtu]

        server_sock.sendto(pack_dio_frag(dio_enum, link_id, 0, not is_frag, data), addr)

    # sends down stream packet as a responce to a up stream packet (or starts lazy wait)
    def down_stream(addr: tuple[str, int], link_id: int, link: DioLink) -> None:
        #print(f"down_stream {link_id}, {link.lazy_addr}, {link.down_buffer}")

        if not link.lazy_addr == None:
            if continue_frag_stream(dio_down_buf, link.lazy_addr, link_id, link):
                link.lazy_addr = addr
                return

            # refresh lazy addr
            if len(link.down_buffer) > 0:
                link.latest_time = time.time() # this is only really here to be in sync with client-side, technically it should not be here
                
                initial_down_stream_transfer(dio_down_buf, link.lazy_addr, link_id, link, link.down_buffer.pop(0))
                link.lazy_addr = addr
            else:
                server_sock.sendto(pack_dio_frag(dio_down_buf, link_id, 0, True, b''), addr)
                link.lazy_addr = addr
        else:
            if continue_frag_stream(dio_down_buf, addr, link_id, link):
                return

            #print(f"down_stream_non_lazy {link_id}, {len(link.down_buffer) > 0}, {link.down_buffer}")
            if len(link.down_buffer) > 0: # do not enter lazy if data still buffered but send data with dio_down_buf
                link.latest_time = time.time() # this is only really here to be in sync with client-side, technically it should not be here

                initial_down_stream_transfer(dio_down_buf, addr, link_id, link, link.down_buffer.pop(0))
            else: # start lazy wait
                link.lazy_addr = addr

    # == quic daemon ==

    quic_threads: dict[int, tuple[threading.Thread, socket.socket]] = {} # TODO: quic conn cleanup

    def quic_daemon(original_destination_connection_id: bytes, quic_server_sock: socket.socket) -> None:
        quic_config = QuicConfiguration(is_client=False)
        quic_config.load_cert_chain(certfile=args.quic_cert, keyfile=args.quic_priv, password=args.quic_passwd)
        
        quic_server = QuicConnection(configuration=quic_config, original_destination_connection_id=original_destination_connection_id)
        quic_streams: dict[int, QuicStream] = {}

        def send_traffic() -> None:
            dgrams_to_send = quic_server.datagrams_to_send(now)
            for dgram in dgrams_to_send:
                quic_server_sock.sendto(dgram[0], dgram[1])

        quic_sel = selectors.DefaultSelector()
        def quic_outbound_daemon() -> None:
            while True:
                try:
                    events = quic_sel.select()
                    for e, mask in events:
                        sock = e.fileobj

                        data = sock.recv(32768)

                        if data:
                            quic_server.send_stream_data(e.data, data)
                        else:
                            quic_server.stop_stream(e.data, 0)

                            quic_sel.unregister(sock)
                            sock.close()
                            quic_streams[e.data].is_localy_closed = True
                    
                    if not len(events) == 0:
                        send_traffic()
                except:
                    print(f"{warn_escape}warn{reset_escape}: exception occured in quic_daemon, trying to continue...")

                    print("------------------------")
                    print(traceback.format_exc(), end="")
                    print("------------------------")

        quic_outbound_thread = threading.Thread(target=quic_outbound_daemon, daemon=True)
        quic_outbound_thread.start()

        # quic server io loop
        while True:
            sleep_time = quic_server.get_timer()
            if not sleep_time == None:
                sleep_time = max(0, sleep_time - time.time()) / 2

            awaiting_socks, _, _ = select.select([quic_server_sock], [], [], sleep_time)

            now = time.time()
            for sock in awaiting_socks:
                dgram = sock.recvfrom(32768)

                quic_server.receive_datagram(dgram[0], dgram[1], now)

            quic_server.handle_timer(now)
            send_traffic()

            while True:
                e = quic_server.next_event()
                if e == None:
                    break

                try:
                    if isinstance(e, StreamDataReceived):
                        stream = quic_streams.get(e.stream_id, None)

                        if stream == None:
                            # init new stream
                            
                            if not e.data.startswith(b'QBD'):
                                print(f"{error_escape}error{reset_escape}: a dio quic stream started without a qbd hello packet, ignoring stream...")
                                quic_server.stop_stream(e.stream_id, 201)
                                continue

                            stream = QuicStream(out_addr=(args.relay_dest, int.from_bytes(e.data[3:5], 'little', signed=False)))
                            stream.out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            stream.out_sock.connect(stream.out_addr)

                            quic_sel.register(stream.out_sock, selectors.EVENT_READ, e.stream_id)

                            e.data = e.data[5:]
                            quic_streams[e.stream_id] = stream

                        elif stream.is_localy_closed:
                            continue

                        stream.out_sock.send(e.data)

                        if e.end_stream:
                            # cleanup old stream

                            quic_sel.unregister(stream.out_sock)
                            stream.out_sock.close()
                            quic_streams.pop(e.stream_id)
                    
                    elif isinstance(e, StopSendingReceived) or isinstance(e, StreamReset):
                        stream = quic_streams.get(e.stream_id, None)

                        if not stream == None:
                            if not stream.is_localy_closed:
                                quic_sel.unregister(stream.out_sock)
                                stream.out_sock.close()
                            quic_streams.pop(e.stream_id)

                except:
                    print(f"{warn_escape}warn{reset_escape}: exception occured in quic_daemon, trying to continue...")

                    print("------------------------")
                    print(traceback.format_exc(), end="")
                    print("------------------------")

    # == outbound daemon ==

    # sends down stream packet if in lazy wait, otherwise buffers the packet for down_stream
    def outbound_down_stream(sock, link_id: int, link: DioLink) -> None:
        data, addr = sock.recvfrom(32768)

        if addr != link.out_addr:
            return

        link.latest_time = time.time()

        # TODO: outbound addr tracking
        if not link.lazy_addr == None:
            if continue_frag_stream(dio_down_buf, link.lazy_addr, link_id, link):
                link.down_buffer.append(data) # lazy addr consumed by frag packet, buffer downstream packet    
            else:
                initial_down_stream_transfer(dio_down_buf, link.lazy_addr, link_id, link, data) # lazy addr consumed -> return dio_down_buf

            link.lazy_addr = None
        else:
            link.down_buffer.append(data)

    def outbound_daemon() -> None:
        while True:
            events = outbound_selector.select(5)
            for e, mask in events:
                outbound_down_stream(e.fileobj, e.data[0], e.data[1])

            inactive_links = []
            for link_id, link in active_links.items():
                if time.time() - link.latest_time > conf_dio_link_timeout:
                    inactive_links.append(link_id)
                    link.out_sock.close()

            for link_id in inactive_links:
                link = active_links.pop(link_id)
                outbound_selector.unregister(link.out_sock)

                print(f"{bold_escape}info{reset_escape}: link_id {link_id} timed out and is now inactive")

    outbound_thread = threading.Thread(target=outbound_daemon, daemon=True)
    outbound_thread.start()

    # == dio daemon ==

    while True:
        try:
            data, addr = server_sock.recvfrom(32768)

            # print(data)

            if data.startswith(b"BD"):
                # serve raw-mode dio packet

                stat_byte: int = int.from_bytes(data[2:3], 'little', signed=False)

                stat_link_id = (stat_byte >> 2) & 0b111111
                stat_enum = stat_byte & 0b11

                if stat_enum == dio_up_trans and stat_link_id:
                    # data transfer

                    link = active_links.get(stat_link_id, None)
                    frag_byte: int = int.from_bytes(data[3:4], 'little', signed=False)

                    if not link == None:
                        link.latest_time = time.time()

                        # assembles the dio frag packets and sends the full packet if finished
                        assemble_up_frag(data[4:], link, frag_byte)

                        down_stream(addr, stat_link_id, link)
                    else:
                        print(f"{warn_escape}warn{reset_escape}: traffic on inactive link: {stat_link_id} from {addr}")

                    continue

                elif stat_enum == dio_up_hearthbeat and stat_link_id:
                    # link heardbeat

                    link = active_links.get(stat_link_id, None)

                    if not link == None:
                        down_stream(addr, stat_link_id, link)
                    else:
                        print(f"{warn_escape}warn{reset_escape}: heartbeat on inactive link_id: {stat_link_id} from {addr}")

                elif stat_enum == dio_up_trans: # and not stat_link_id
                    # special control packet

                    quic_rebind = data.startswith(b'qrb', 3)

                    if quic_rebind or data.startswith(b'rb', 3):
                        # rebind

                        for link_id in range(1, 64):
                            if not link_id in active_links:
                                link = DioLink(latest_time=time.time(), up_link_mtu=int.from_bytes(data[7:9], 'little', signed=False), down_link_mtu=int.from_bytes(data[9:11], 'little', signed=False))
                                link.out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                                print(f"{bold_escape}info{reset_escape}: accepted a new {'quic' if quic_rebind else ''} rebind request with link_id {link_id}")

                                active_links[link_id] = link
                                outbound_selector.register(link.out_sock, selectors.EVENT_READ, (link_id, link))

                                if not quic_rebind:
                                    link.out_addr = (args.relay_dest, int.from_bytes(data[5:7], 'little', signed=False))
                                else:
                                    quic_server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                    quic_server_sock.bind(('127.0.0.1', 0))

                                    link.out_addr = quic_server_sock.getsockname() # qrb port is ignored here and is communicated inside the quic conn
                                    
                                    quic_thread = threading.Thread(target=quic_daemon, args=(data[12:], quic_server_sock), daemon=True)
                                    quic_thread.start()

                                    quic_threads[link_id] = (quic_thread, quic_server_sock)

                                server_sock.sendto(pack_dio(dio_down_trans, 0, b'rb' + link_id.to_bytes(1, 'little', signed=False)), addr)

                                break

                elif stat_enum == dio_up_hearthbeat: # and not stat_link_id 
                    # dio test ping

                    server_sock.sendto(pack_dio(dio_down_trans, 0, b'pong'), addr)

                else:
                    print(f"{warn_escape}warn{reset_escape}: unknown dio packet from {addr} (parsed link_id: {stat_link_id} enum: {stat_enum})")

            else: # TODO
                pass

        except KeyboardInterrupt:
            print(f"{bold_escape}info{reset_escape}: stopping btr dio server...")
            exit(0)

        except:
            print(f"{warn_escape}warn{reset_escape}: exception occured, trying to continue...")

            print("------------------------")
            print(traceback.format_exc(), end="")
            print("------------------------")

@dataclasses.dataclass(kw_only=True)
class DioTunnel:
    tun_sock: socket.socket = dataclasses.field(init=False)
    tun_ports: tuple[int, int] = dataclasses.field(default_factory=tuple)

    active_link_ids: dict[tuple[str, int], int] = dataclasses.field(default_factory=dict)
    is_quic_link: bool
    original_destination_connection_id: bytes | None = None # quic only

@dataclasses.dataclass(kw_only=True)
class ClientQuicStream:
    inbound_sock: socket.socket
    peer_addr: tuple[str, int]
    is_localy_closed: bool = False

@dataclasses.dataclass(kw_only=True)
class DioClientLink:
    owning_tunnel: DioTunnel
    local_addr: tuple[str, int] 

    # frag assebly is described in dio-serve
    down_frag_buf: dict[int, bytes] = dataclasses.field(default_factory=dict)

    up_frag_buf: bytes = dataclasses.field(default_factory=bytes)
    up_frag_index: int = 0

    timestamp: float
    heartbeat_timestamp: float

def btr_dio_tunnel(args: argparse.Namespace):
    try:
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.connection import QuicConnection
        from aioquic.quic.events import StreamDataReceived, StopSendingReceived, StreamReset
    except ImportError:
        print(f"{error_escape}error{reset_escape}: failed to import aioquic module which is required by btr dio")
        exit(-1)

    if not args.relay_addr:
        print(f"{error_escape}error{reset_escape}: no relay addr specified")
        exit(-1)

    relay_addr = args.relay_addr.split(':', 2)
    if len(relay_addr) != 2:
        print(f"{error_escape}error{reset_escape}: no relay addr port specified (use `:[port]` to specify on which port to connect)")
        exit(-1)
    relay_addr = (socket.gethostbyname(relay_addr[0]), int(relay_addr[1]))

    if not args.quic_cert:
        print(f"{error_escape}error{reset_escape}: no certificates specified which are required by btr dio")
        exit(-1)

    print(f"{bold_escape}info{reset_escape}: starting btr dio tunneling daemon...")

    active_links: dict[int, DioClientLink] = {}
    relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    up_relay_mtu: int = 15
    down_relay_mtu: int = 15

    sel = selectors.DefaultSelector()
    
    active_tunnels = []
    for tun in args.udp_tunnels:
        tunnel_ports = tun.split(':', 2)
        if len(tunnel_ports) == 1:
            tunnel_ports = (tunnel_ports[0], tunnel_ports[0])
        tunnel_ports = (int(tunnel_ports[0]), int(tunnel_ports[1]))
        
        tunnel = DioTunnel(tun_ports=tunnel_ports, is_quic_link=False)

        tunnel.tun_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # tunnel.tun_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        tunnel.tun_sock.bind(('', tunnel_ports[0]))

        sel.register(tunnel.tun_sock, selectors.EVENT_READ, tunnel)
        active_tunnels.append(tunnel)

        if args.verbose:
            print(f"{bold_escape}verbose{reset_escape}: new dio udp tunnel for {tunnel_ports[0]}:{tunnel_ports[1]}")

    # takes and tries to assemble a full packet from dio frag packets
    def assemble_down_frag(data: bytes, link: DioClientLink, frag_byte: int) -> None:
        if frag_byte & dio_frag_all:
            if len(link.down_frag_buf) == (dio_frag_mask & frag_byte):
                # frag packet complete, send

                link.down_frag_buf[dio_frag_mask & frag_byte] = data
                link.owning_tunnel.tun_sock.sendto(b''.join(link.down_frag_buf.values()), link.local_addr)
            else:
                pass # frag packet incomplete, consider lost
            
            link.down_frag_buf = {}
        else:
            # frag packet, append to frag_buf

            link.down_frag_buf[frag_byte] = data

    # continues sending frag packets if there's a frag packet on progress
    def continue_frag_stream(link_id: int, link: DioClientLink) -> bool:
        if len(link.up_frag_buf) == 0:
            return False

        link.timestamp = time.time()
        
        if len(link.up_frag_buf) <= up_relay_mtu:
            frag = link.up_frag_buf
            frag_index = link.up_frag_index
            frag_fin = True

            link.up_frag_buf = b""
            link.up_frag_index = 0
        else:
            frag = link.up_frag_buf[:up_relay_mtu]
            frag_index = link.up_frag_index
            frag_fin = False

            link.up_frag_buf = link.up_frag_buf[up_relay_mtu:]
            link.up_frag_index += 1

        relay_sock.sendto(pack_dio_frag(dio_up_trans, link_id, frag_index, frag_fin, frag), relay_addr)
        return True

    # helper that takes care of fragmentation if nessesary
    def inbound_up_stream(link_id: int, link: DioClientLink, data: bytes):
        if len(data) > 127 * up_relay_mtu:
            print(f"{warn_escape}warn{reset_escape}: packet exceeded maximum allowed mtu of {127 * up_relay_mtu} bytes, ignoring...")
            return

        link.timestamp = time.time()
        is_frag = len(data) > up_relay_mtu

        if is_frag:
            link.up_frag_buf = data

            while continue_frag_stream(link_id, link):
                pass # TODO: wait here to not get rate limit?
        else:
            relay_sock.sendto(pack_dio_frag(dio_up_trans, link_id, 0, True, data), relay_addr)

    def tunnel_read(tun: DioTunnel):
        data, local_addr = tun.tun_sock.recvfrom(32768)

        if local_addr == relay_addr:
            return

        link_id = tun.active_link_ids.get(local_addr)
        
        if not link_id == None:
            link = active_links.get(link_id)
            if link == None:
                tun.active_link_ids.pop(local_addr)
                link_id = None

        if link_id == None:
            # new connection, establish new link
            # might lag ALL btr tunnels if responce is lost but good enough

            received = False
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            for i in range(5):
                if not tun.is_quic_link:
                    temp_sock.sendto(pack_dio(dio_up_trans, 0, b''.join((b"rb", tun.tun_ports[1].to_bytes(2, 'little', signed=False), up_relay_mtu.to_bytes(2, 'little', signed=False), down_relay_mtu.to_bytes(2, 'little', signed=False)))), relay_addr)
                else:
                    if tun.original_destination_connection_id == None:
                        print(f"{error_escape}error{reset_escape}: original_destination_connection_id not assigned to a quic tunnel before rebind, this is a bug, ignoring...")
                        continue

                    temp_sock.sendto(pack_dio(dio_up_trans, 0, b''.join((b"qrb", b"\x00\x00", up_relay_mtu.to_bytes(2, 'little', signed=False), down_relay_mtu.to_bytes(2, 'little', signed=False), tun.original_destination_connection_id))), relay_addr)

                read_socks, _, _ = select.select([temp_sock], [], [], .5)
                if len(read_socks) == 0:
                    if args.verbose:
                        print(f"{bold_escape}verbose{reset_escape}: retrying new link request... {i + 1}/5")
                    continue

                rb_data, recv_addr = temp_sock.recvfrom(32768)

                if relay_addr != recv_addr:
                    raise ValueError(f"different recv addr when requesting new link; relay: {relay_addr} recv: {recv_addr}")

                if not rb_data.startswith(b"BD"):
                    print(f"{warn_escape}warn{reset_escape}: non dio packet received, ignoring...")
                    i -= 1
                    continue

                if rb_data.startswith(b"\x00", 2):
                    # rebind success!

                    link_id = int.from_bytes(rb_data[5:6], 'little', signed=False)
                    tun.active_link_ids[local_addr] = link_id
                    link = DioClientLink(owning_tunnel=tun, local_addr=local_addr, timestamp=time.time(), heartbeat_timestamp=0)
                    active_links[link_id] = link

                    print(f"{bold_escape}info{reset_escape}: establised a new dio link (id: {link_id}) for {local_addr}")

                    received = True
                    break
                elif rb_data.startswith(b"\x08", 2):
                    # rebind failed!

                    print(f"{error_escape}error{reset_escape}: failed to establish a new link with server, all links might be in use!")
                    
                    received = True
                    break
                else:
                    print(rb_data)
                    raise ValueError("non dio packet stat byte when requesting new link")

            temp_sock.close()

            if not received:
                print(f"{error_escape}error{reset_escape}: no response from server when trying to establish a new link!")
                return

        # dio up
        inbound_up_stream(link_id, link, data)
    
    def inbound_daemon():
        while True:
            events = sel.select()
            for key, mask in events:
                tunnel_read(key.data)
    
    def cleanup_daemon():
        cleanup_finished = True
        
        while True:
            if cleanup_finished:
                time.sleep(1)

            cleanup_finished = True
            for tun in active_tunnels:
                inactive_addrs = []
                for addr, link_id in tun.active_link_ids.items():
                    if time.time() - active_links[link_id].timestamp > conf_dio_link_timeout:
                        active_links.pop(link_id)
                        inactive_addrs.append(addr)

                        print(f"{bold_escape}info{reset_escape}: assuming link id: {link_id} to be inactive")
                    elif min(time.time() - active_links[link_id].heartbeat_timestamp, time.time() - active_links[link_id].timestamp) > conf_dio_heartbeat_time or len(active_links[link_id].down_frag_buf) != 0:
                        active_links[link_id].heartbeat_timestamp = time.time()
                        relay_sock.sendto(pack_dio(dio_up_hearthbeat, link_id, b""), relay_addr)

                        if len(active_links[link_id].down_frag_buf) != 0:
                            cleanup_finished = False
                    
                for addr in inactive_addrs:
                    tun.active_link_ids.pop(addr)

    inbound_thread = threading.Thread(target=inbound_daemon, daemon=True)
    inbound_thread.start()

    cleanup_thread = threading.Thread(target=cleanup_daemon, daemon=True)
    cleanup_thread.start()

    # == quic daemon ==

    quic_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    quic_client_sock.bind(('127.0.0.1', 0))

    quic_tunnel_port_map: dict[int, int] = {}
    quic_tunnel_port = 0
    listening_inbound_quic_socks: list[socket.socket] = []

    # create quic dedicated tunnel

    transport_tun_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    transport_tun_sock.bind(('', 0))
    
    quic_tunnel_port = transport_tun_sock.getsockname()[1]
    quic_transport_tunnel = DioTunnel(tun_ports=(quic_tunnel_port, 40443), is_quic_link=True)
    quic_transport_tunnel.tun_sock = transport_tun_sock

    sel.register(quic_transport_tunnel.tun_sock, selectors.EVENT_READ, quic_transport_tunnel)
    active_tunnels.append(quic_transport_tunnel)

    for tun in args.tcp_tunnels:
    # if args.tcp_tunnel:

        tunnel_ports = tun.split(':', 2)
        if len(tunnel_ports) == 1:
            tunnel_ports = (tunnel_ports[0], tunnel_ports[0])
        tunnel_ports = (int(tunnel_ports[0]), int(tunnel_ports[1]))

        tun_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # tun_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        tun_sock.bind(('', tunnel_ports[0]))
        tun_sock.listen(20)

        listening_inbound_quic_socks.append(tun_sock)
        quic_tunnel_port_map[tunnel_ports[0]] = tunnel_ports[1]

        if args.verbose:
            print(f"{bold_escape}verbose{reset_escape}: created a quic tunnel for ports {tunnel_ports[0]}:{tunnel_ports[1]}")

    def quic_daemon() -> None:
        quic_config = QuicConfiguration()
        quic_config.load_cert_chain(certfile=args.quic_cert)
        quic_config.load_verify_locations(cafile=args.quic_cert) # mark self-signed cert as trusted
        
        quic_client = QuicConnection(configuration=quic_config)
        quic_streams: dict[int, ClientQuicStream] = {}

        quic_transport_tunnel.original_destination_connection_id = quic_client.original_destination_connection_id

        quic_client.connect(('127.0.0.1', quic_tunnel_port), time.time())

        def send_traffic() -> None:
            dgrams_to_send = quic_client.datagrams_to_send(time.time())
            for dgram in dgrams_to_send:
                quic_client_sock.sendto(dgram[0], dgram[1])

        quic_sel = selectors.DefaultSelector()
        def quic_outbound_daemon() -> None:
            while True:
                try:
                    events = quic_sel.select()
                    for e, mask in events:
                        sock = e.fileobj

                        data = sock.recv(32768)

                        if data:
                            quic_client.send_stream_data(e.data, data)
                        else:
                            quic_client.stop_stream(e.data, 0)

                            quic_sel.unregister(sock)
                            sock.close()
                            quic_streams[e.data].is_localy_closed = True
                    
                    if not len(events) == 0:
                        send_traffic()
                except:
                    print(f"{warn_escape}warn{reset_escape}: exception occured in quic_daemon, trying to continue...")

                    print("------------------------")
                    print(traceback.format_exc(), end="")
                    print("------------------------")

        quic_outbound_thread = threading.Thread(target=quic_outbound_daemon, daemon=True)
        quic_outbound_thread.start()

        # quic server io loop
        while True:
            sleep_time = quic_client.get_timer()
            if not sleep_time == None:
                sleep_time = min(max(0, sleep_time - time.time()) / 2, 2)

            awaiting_socks, _, _ = select.select([quic_client_sock] + listening_inbound_quic_socks, [], [], sleep_time)

            now = time.time()
            for sock in awaiting_socks:
                if sock == quic_client_sock:
                    dgram = sock.recvfrom(32768)

                    quic_client.receive_datagram(dgram[0], dgram[1], now)
                else:
                    new_conn = sock.accept()

                    stream_id = quic_client.get_next_available_stream_id()
                    stream = ClientQuicStream(inbound_sock=new_conn[0], peer_addr=new_conn[1])

                    quic_client.send_stream_data(stream_id, b'QBD' + quic_tunnel_port_map[sock.getsockname()[1]].to_bytes(2, 'little', signed=False))

                    quic_sel.register(stream.inbound_sock, selectors.EVENT_READ, stream_id)
                    quic_streams[stream_id] = stream

                    print(f"{bold_escape}info{reset_escape}: established a new quic stream for {new_conn[1]}")

            quic_client.handle_timer(now)
            send_traffic()

            while True:
                e = quic_client.next_event()
                if e == None:
                    break

                try:
                    if isinstance(e, StreamDataReceived):
                        stream = quic_streams[e.stream_id]

                        if stream.is_localy_closed:
                            continue

                        stream.inbound_sock.send(e.data)

                        if e.end_stream:
                            # cleanup old stream

                            print(f"{bold_escape}info{reset_escape}: closing quic stream for {stream.peer_addr}")

                            quic_sel.unregister(stream.inbound_sock)
                            stream.inbound_sock.close()
                            quic_streams.pop(e.stream_id)
                    
                    if isinstance(e, StopSendingReceived) or isinstance(e, StreamReset):
                        stream = quic_streams.get(e.stream_id, None)

                        if not stream == None:
                            print(f"{bold_escape}info{reset_escape}: closing quic stream for {stream.peer_addr}")

                            if not stream.is_localy_closed:
                                quic_sel.unregister(stream.inbound_sock)
                                stream.inbound_sock.close()
                            quic_streams.pop(e.stream_id)

                except:
                    print(f"{warn_escape}warn{reset_escape}: exception occured in quic_daemon, trying to continue...")

                    print("------------------------")
                    print(traceback.format_exc(), end="")
                    print("------------------------")

    quic_thread = threading.Thread(target=quic_daemon, daemon=True)
    quic_thread.start()

    # == main client io loop ==

    try:
        while True:
            data, recv_addr = relay_sock.recvfrom(32768)

            # print(data)

            if relay_addr != recv_addr:
                raise ValueError(f"different recv addr; relay: {relay_addr} recv: {recv_addr}")

            if not data.startswith(b"BD"):
                print(f"{warn_escape}warn{reset_escape}: non dio packet received, ignoring...")
                continue

            stat_byte: int = int.from_bytes(data[2:3], 'little', signed=False)

            stat_link_id = (stat_byte >> 2) & 0b111111
            stat_enum = stat_byte & 0b11

            if stat_link_id == 0:
                print(f"{error_escape}error{reset_escape}: unexpected link_id 0 special packet with enum {stat_enum}, this is a bug, ignoring...")
                continue

            if not stat_link_id in active_links:
                print(f"{error_escape}error{reset_escape}: received data from link not attached to this device, this is a bug, ignoring...")
                continue

            link = active_links[stat_link_id]

            # dio down
            if stat_enum == dio_down_trans or stat_enum == dio_down_buf:
                frag_byte: int = int.from_bytes(data[3:4], 'little', signed=False)

                if data[4:] == b"":
                    continue

                assemble_down_frag(data[4:], link, frag_byte)
                link.timestamp = time.time()

                if stat_enum == dio_down_buf:
                    # packets are still buffered with no lazy addr on relay
                    relay_sock.sendto(pack_dio(dio_up_hearthbeat, stat_link_id, b""), relay_addr)
            else:
                print(f"{warn_escape}warn{reset_escape}: unknown dio packet from relay (parsed link_id: {stat_link_id} enum: {stat_enum})")

    except KeyboardInterrupt:
        print(f"{bold_escape}info{reset_escape}: stopping btr dio tunneling daemon...")
        exit(0)

    # except:


def route_chrome(args: argparse.Namespace):
    if not args.relay_addr:
        print(f"{error_escape}error{reset_escape}: no socks5 proxy specified")
        exit(-1)

    print(f"{bold_escape}info{reset_escape}: starting socks5 chrome session...")

    if args.verbose:
        print(f"> {args.chrome_exec} --proxy-server=\"socks5://{args.relay_addr}\" --host-resolver-rules=\"MAP * ~NOTFOUND , EXCLUDE {args.relay_addr.split(':', 2)[0]}\"")

    os.system(f"{args.chrome_exec} --proxy-server=\"socks5://{args.relay_addr}\" --host-resolver-rules=\"MAP * ~NOTFOUND , EXCLUDE {args.relay_addr.split(':', 2)[0]}\"")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A couple of utilities that follow the rules.", formatter_class=argparse.RawTextHelpFormatter,
    epilog="""example usage: 
    `./btr.py open-tun proxy.local:3128 my_relay.net -t 5900:443`
    `./btr.py dio-raw-tun my_relay.net:1058 -u 48965:1082`
    `./btr.py route-chrome localhost:1080 --chrome-exec chromium`
    `./btr.py direct-tun blahblah_wont_be_used my_relay.net -t 5646:22`""")

    print("By-The-Rules Utilities v0.8")
    
    print("""   ___ _________ 
  / _ )_  __/ _ \\
 / _  |/ / / , _/
/____//_/ /_/|_|      
""")

    parser.add_argument("mode", type=str, nargs="?", choices=["open-tun", "route-chrome", "direct-tun", "dproxy-tun", "dio-serve", "dio-raw-tun"],
                        help=
"""select btr mode to run in:
    open-tun - starts a btr tunnel without any special routing (needs non-filtered access to the relay)
    dio-serve - starts hosting a btr dio server on [addr]
    dio-raw-tun - starts a btr dio tunnel, [addr] should point to a running dio server
    dproxy-tunnel - starts a btr tunnel in a whitelist dproxy mode (TODO)
    direct-tun - starts a btr tunnel without a proxy connection (for testing)
    route-chrome - a helper for launching a chrome session routed trough a socks5 proxy (can be used with ssh dyn tunnels)""")

    parser.add_argument("relay_addr", type=str, nargs="?",
                        help="the server where tunnels are redirected to, from there you can relay your traffic")
    
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose",
                        help="enable verbose output")

    parser.add_argument("--proxy", type=str, dest="proxy_addr",
                        help="the http proxy used for creation of a open-tun (or socks5 in route-chrome)")

    tunnel_group = parser.add_argument_group("*-tun mode only")

    tunnel_group.add_argument("-t", "--tcp-tunnel", type=str, dest="tcp_tunnels", default=[], action="append",
                        help="create a tcp tunnel to relay for a specified port")
    
    tunnel_group.add_argument("-p", "--pool-size", type=int, dest="pool_size", default=0,
                        help="number of tcp tunnels to relay to hold open even when not in use, useful for perservation of connections after a filter change")
    
    tunnel_group.add_argument("-r", "--enable-reuse", action="store_true", dest="enable_reuse",
                        help="enables connection reuse (refilling of the idle pool)\n\
note connection reuse support *will* vary between protocols (ssh after exit won't work, direct http reuse might)")

    dio_group = parser.add_argument_group("dio mode only")

    dio_group.add_argument("-u", "--udp-tunnel", type=str, dest="udp_tunnels", default=[], action="append",
                        help="create a udp tunnel to relay for a specified port")

    dio_group.add_argument("-f", "--forward-relay", type=str, dest="relay_dest", default="127.0.0.1",
                        help="(only for dio-serve) where to redirect tunneled dio packets, by default to loopback")

    dio_group.add_argument("--cert", type=str, dest="quic_cert",
                        help="certs used for built-in tls in btr dio")
    dio_group.add_argument("--priv", type=str, dest="quic_priv",
                        help="(dio-serve only) priv key used for built-in tls in btr dio")
    dio_group.add_argument("--pass", type=str, dest="quic_passwd",
                        help="(dio-serve only) pass used for built-in tls in btr dio")

    chrome_group = parser.add_argument_group("route-chrome mode only")

    chrome_group.add_argument("--chrome-exec", type=str, default="start chrome" if os.name == 'nt' else "chromium", dest="chrome_exec",
                        help="command to start chrome")

    args = parser.parse_args()

    if args.mode == None:
        print(f"{error_escape}error{reset_escape}: no btr mode specified")
        exit(-1)
    
    elif args.mode == "open-tun":
        btr_socket_daemon(open_tunnel, args)

    elif args.mode == "direct-tun":
        btr_socket_daemon(direct_tunnel, args)

    elif args.mode == "dproxy-tun":
        print(f"{error_escape}error{reset_escape}: dproxy mode has not yet been implemented")
        exit(-1)

    elif args.mode == "dio-serve":
        btr_dio_serve(args)
    
    elif args.mode == "dio-raw-tun":
        btr_dio_tunnel(args)
    
    elif args.mode == "route-chrome":
        route_chrome(args)
