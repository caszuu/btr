#!/usr/bin/env python3

import argparse
import socket
import selectors
import subprocess
import tarfile
import shutil
import atexit
import os

bold_escape = "\033[1m"
reset_escape = "\033[0m"

error_escape = "\033[31m"
warn_escape = "\033[33m"

# starts a python-native udp tunnel/redirect server on localhost (this is the only tunnel mode that does not operate over a ssh session)
# based on udp-relay.py by Etienne Perot (https://github.com/EtiennePerot/misc-scripts/blob/master/udp-relay.py)
def udp_tunnel(config: dict):
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', config["relay_port"]))

    print(f" [{config['name']}] starting a udp relay tunnel on port {config['relay_port']}")

    knownClient = None
    knownServer = (config["relay_dest"], config["relay_port"])

    try:
        while True:
            data, addr = sock.recvfrom(32768)

            if addr == knownClient:
                sock.sendto(data, knownServer)

            elif addr == knownServer:
                sock.sendto(data, knownClient)

            else:
                if knownClient is None:
                    knownClient = addr
                    sock.sendto(data, knownServer)
                
                else:
                    print(f"> [{config['name']}] {warn_escape}warning{reset_escape}: ignoring packet from unknown peer {addr[0]}:{addr[1]}")

    except KeyboardInterrupt:
        sock.close()

        print(f"> [{config['name']}] stopping udp relay")
        exit(0)

# ssh based TCP tunneling daemon
def ssh_tunnel(args: argparse.Namespace):
    tunnel_args = []
    
    if args.relay_host == None:
        print(f"{error_escape}error{reset_escape}: no relay host specified")
        exit(-1)

    if not args.ssh_key_file == None:
        tunnel_args += ("-i", args.ssh_key_file)

    if not args.tcp_tunnels == None:
        for t in args.tcp_tunnels:
            tunnel_args += ("-L", f"{t[0]}:{args.bind_address}:{t[1]}")

    if not args.dyn_tunnels == None:
        for t in args.dyn_tunnels:
            tunnel_args += ("-D", str(t))

    # udp relays run in subprocesses to increase throughput
    udp_daemons = []

    if not args.udp_tunnels == None:
        udp_hostname = args.relay_host.split("@")[-1]

        for t in args.udp_tunnels:
            udp_daemons.append(subprocess.Popen([f"{args.local_venv}python", "-c", f"import btr; btr.udp_tunnel({{'name': 'relay-{t}', 'relay_port': {t}, 'relay_dest': '{udp_hostname}'}})"]))

    # cleanup udp daemons on exit
    atexit.register(lambda: [d.terminate() for d in udp_daemons])

    print("starting ssh tunnel session...")

    if args.verbose:
        print("> " + " ".join(["ssh"] + tunnel_args + [args.relay_host] + ["-N"]))

    ssh_daemon = subprocess.Popen(["ssh"] + tunnel_args + [args.relay_host] + ["-N"])

    try:
        # if ssh exits before a keyboard interrupt, count it as a error and forward the exit code
        exit(ssh_daemon.wait())
    except KeyboardInterrupt:
        ssh_daemon.terminate()

        print("stopping ssh session...")

# a helper that proxies chrome trafic through a ssh dynamic tunnel
def proxy(args: argparse.Namespace):
    tunnel_args = []
    
    if args.relay_host == None:
        print(f"{error_escape}error{reset_escape}: no relay host specified")
        exit(-1)

    if not args.ssh_key_file == None:
        tunnel_args += ("-i", args.ssh_key_file)
    
    # setup chrome proxy tunnel
    tunnel_args += ("-D", str(args.proxy_port))

    print("starting ssh proxy session...")
    if args.verbose:
        print("> " + " ".join(["ssh"] + tunnel_args + [args.relay_host] + ["-N"]))

    ssh_daemon = subprocess.Popen(["ssh"] + tunnel_args + [args.relay_host] + ["-N"])

    print("starting socks5 chrome session...")
    if args.verbose:
        print(f"> {args.chrome_exec} --proxy-server=\"socks5://localhost:{args.proxy_port}\" --host-resolver-rules=\"MAP * ~NOTFOUND , EXCLUDE localhost\"")

    os.system(f"{args.chrome_exec} --proxy-server=\"socks5://localhost:{args.proxy_port}\" --host-resolver-rules=\"MAP * ~NOTFOUND , EXCLUDE localhost\"")

    try:
        # if ssh exits before a keyboard interrupt, count it as a error and forward the exit code
        exit(ssh_daemon.wait())
    except KeyboardInterrupt:
        ssh_daemon.terminate()

        print("stopping ssh session...")

# bootstrap pip with PySocks for proxied pip usage (note: currently requires no-password and no-warning ssh login due to a `cat over ssh` file transfer)
def bootstrap(args: argparse.Namespace):
    ssh_args = []
    
    if args.relay_host == None:
        print(f"{error_escape}error{reset_escape}: no relay host specified")
        exit(-1)

    if not args.ssh_key_file == None:
        ssh_args += ("-i", args.ssh_key_file)

    print("preparing bootstrap prefix...")
    if args.verbose:
        print("> " + " ".join(["ssh"] + [args.relay_host] + ssh_args + ["python3 -m pip download pysocks -d \"btr-deps\" && tar -cvzf btr-prefix.tar.gz btr-deps && rm -rf btr-deps"]))

    result = subprocess.call(["ssh"] + [args.relay_host] + ssh_args + ["python3 -m pip download pysocks -d \"btr-deps\" && tar -cvzf btr-prefix.tar.gz btr-deps && rm -rf btr-deps"])

    if result != 0:
        print(f"{error_escape}error{reset_escape}: error while preparing bootstrap prefix on relay")
        exit(result)
    
    print("\ntransfering bootstrap prefix...")
    if args.verbose:
        print("> " + " ".join(["ssh"] + [args.relay_host] + ssh_args + ["cat btr-prefix.tar.gz", " > btr-prefix.tar.gz"]))        

    with open("btr-prefix.tar.gz", "wb") as f:
        result = subprocess.call(["ssh"] + [args.relay_host] + ssh_args + ["cat btr-prefix.tar.gz"], stdout=f)
    
    if result != 0:
        print(f"{error_escape}error{reset_escape}: error while transfering bootstrap prefix from relay")
        exit(result)
    
    print("\ncleaning up relay prefix...")
    if args.verbose:
        print("> " + " ".join(["ssh"] + [args.relay_host] + ssh_args + ["rm btr-prefix.tar.gz"]))

    subprocess.call(["ssh"] + [args.relay_host] + ssh_args + ["rm btr-prefix.tar.gz"])

    print("\ninstalling bootstrap prefix...")
    
    # extract
    tarfile.open("btr-prefix.tar.gz").extractall("./btr-prefix")
    
    # install
    result = os.system(f"{args.local_venv}python3 -m pip install ./btr-prefix/btr-deps/* -f ./btr-prefix/btr-deps --no-index")

    if result != 0:
        print(f"{error_escape}error{reset_escape}: error while installing bootstrap prefix")
        exit(result)

    # clean up
    shutil.rmtree("./btr-prefix")
    os.remove("btr-prefix.tar.gz")

    print("\nto use pip with a btr proxy, run pip with the `--proxy` flag while running a btr dyn_tunnel in bg, eg. `pip install pygame --proxy socks5://localhost:1080`")

# TODO: to perform a relay-to-client punch-trough client endpoint would be needed to be retrieved (not found a way to do with raw http or icmp) 
def tcp_white_punch(config: dict):
    whitelist_peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    whitelist_peer_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    whitelist_peer_sock.bind(('', 0))
    local_tunnel_addr = whitelist_peer_sock.getsockname()

    local_sock.bind(('', config["local_port"]))

    whitelist_peer_sock.connect((socket.gethostbyname("wikipedia.org"), 443))
    # local_sock.connect((config["relay_addr"], config["relay_port"]))
    local_sock.listen(24)
    local_sock.setblocking(False)

    print(f"[{config['local_port']} -> {config['relay_port']}] starting whitelist hidden tcp tunnel for port {config['relay_port']}")

    sel = selectors.DefaultSelector()
    active_work_socks = []

    def read_work_conn(rsock, wsock):
        data = rsock.recv(32768)

        if data:
            wsock.send(data)
        else:
            if rsock.getpeername()[1] == config["relay_port"]:
                print(f"[{config['local_port']} -> {config['relay_port']}] closing work conn from {rsock.getsockname()}")
            sel.unregister(rsock)
            
            rsock.close()

    def accept_work_conn(sock, _):
        conn, addr = sock.accept()
        conn.setblocking(False)

        # create a new connection to relay
        rsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        rsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            rsock.connect((config["relay_addr"], config["relay_port"]))
            rsock.setblocking(False)
        except ConnectionError:
            conn.close()
            return

        print(f"[{config['local_port']} -> {config['relay_port']}] accepting new work conn from {addr}")

        sel.register(conn, selectors.EVENT_READ, (read_work_conn, rsock))
        sel.register(rsock, selectors.EVENT_READ, (read_work_conn, conn))
    
    sel.register(local_sock, selectors.EVENT_READ, (accept_work_conn, None))

    while True:
        events = sel.select()
        for key, mask in events:
            callback = key.data[0]
            callback(key.fileobj, key.data[1])

# note: in testing only
def white_proxy(args: argparse.Namespace):
    if args.relay_host == None:
        print(f"{error_escape}error{reset_escape}: no relay host specified")
        exit(-1)

    # tcp tunnels
    tcp_daemons = []

    if not args.tcp_tunnels == None:
        relay_addr = args.relay_host.split("@")[-1]

        for t in args.tcp_tunnels:
            tcp_daemons.append(subprocess.Popen([f"{args.local_venv}python", "-c", f"import btr; btr.tcp_white_punch({{'local_port': {t[0]}, 'relay_port': {t[1]}, 'relay_addr': '{relay_addr}'}})"]))

    atexit.register(lambda: [d.terminate() for d in tcp_daemons])

    try:
        while True:
            pass # idle main process while daemon subprocesses run in bg
    except KeyboardInterrupt:
        print("stopping whitelist tunnels...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A couple of utilities that follow the rules.", formatter_class=argparse.RawTextHelpFormatter,
    epilog="""example usage: 
    `./btr.py tunnel user@my_host.net -t 5900 -i .ssh/rsa_key`
    `./btr.py chrome-proxy user@my_host.net -i .ssh/rsa_key`
    `./btr.py punch-proxy my_host.net -t 5646:22`""")

    parser.add_argument("mode", type=str, nargs="?", choices=["tunnel", "chrome-proxy", "bootstrap", "punch-proxy"],
                        help=
"""selects btr utility to run:
    tunnel - ssh + (very basic) python-native udp relay based tunnelling daemon
    chrome-proxy - a chrome + ssh socks5 proxy helper and daemon
    bootstrap - download and install pysocks for pip usage using a socks5 proxy
    punch-proxy - python-native tcp + udp tunnelling daemon with support for whitelist firewall \"punch-through\"""")

    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose",
                        help="enable verbose output")
    parser.add_argument("--venv", type=str, dest="local_venv", default="",
                        help="the path to the local virtual environment to use (by default, uses the system environment)")

    # ssh tunnels

    parser.add_argument("-b", "--bind-address", type=str, default="localhost", dest="bind_address",
                        help="the address to bind to for ssh tunnels (localhost by default, note that `GatewayPorts` must be enabled on relay for other addresses to be allowed)")
    parser.add_argument("-t", "--tunnel", type=str, default=[], action="append", dest="tcp_tunnels",
                        help="create a tcp tunnel to relay for a specified port")
    parser.add_argument("-dt", "--dyn-tunnel", type=int, default=[], action="append", dest="dyn_tunnels",
                        help="create a ssh dynamic tunnel to relay for a specified port")
    parser.add_argument("-i", type=str, dest="ssh_key_file",
                        help="the path to a ssh key file used for relay")

    # udp tunnel daemon

    parser.add_argument("-ut", "--udp-tunnel", type=int, default=[], action="append", dest="udp_tunnels",
                        help="create a udp relay tunnel to relay for a specified port")

    # proxy

    parser.add_argument("-p", "--proxy-port", type=int, default=1080, dest="proxy_port",
                        help="which port to use on localhost for the tunneled socks5 proxy")
    parser.add_argument("--chrome-exec", type=str, default="start chrome" if os.name == 'nt' else "chromium", dest="chrome_exec",
                        help="command to start chrome")

    # relay

    parser.add_argument("relay_host", type=str, nargs="?",
                        help="the relay address which will be used as the ssh host")

    args = parser.parse_args()

    if args.local_venv != "":
        args.local_venv = args.local_venv + "/bin/"

    if not args.tcp_tunnels == None:
        for i in range(len(args.tcp_tunnels)):
            args.tcp_tunnels[i] = args.tcp_tunnels[i].split(":", 2) if len(args.tcp_tunnels[i].split(":", 2)) == 2 else (args.tcp_tunnels[i], args.tcp_tunnels[i])

    print("By-The-Rules Utilities v0.4")
    
    print("""   ___ _________ 
  / _ )_  __/ _ \\
 / _  |/ / / , _/
/____//_/ /_/|_|      
""")
    
    if args.mode == None:
        print(f"{error_escape}error{reset_escape}: no btr mode specified")
        exit(-1)

    elif args.mode == "tunnel":
        ssh_tunnel(args)

    elif args.mode == "chrome-proxy":
        proxy(args)

    # elif args.mode == "firefox-proxy":
    #     pass # proxy(args)

    elif args.mode == "bootstrap":
        bootstrap(args)

    elif args.mode == "punch-proxy":
        white_proxy(args)

    else:
        print(f"{error_escape}error{reset_escape}: unknown btr mode: {args.mode}")
