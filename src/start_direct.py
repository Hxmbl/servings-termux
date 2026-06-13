import os, sys, threading, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pathlib import Path
from src.http_server import _http_server, BootHTTPHandler
from src.tftp import _tftp_listener
from src.dhcp_server import dhcp_listener

boot_dir = Path(os.path.expanduser("~/boot"))
os.makedirs(boot_dir, exist_ok=True)
BootHTTPHandler.extra_paths = [Path("/sdcard/Disk Images")]

server_ip = os.environ.get("SERVER_IP", "192.168.123.249")
http_port = int(os.environ.get("HTTP_PORT", "8081"))
boot_url = f"http://{server_ip}:{http_port}/boot.cfg"

# Kill Android dnsmasq or any port 67 holder
os.system("su -c 'killall dnsmasq 2>/dev/null; fuser -k 67/udp 2>/dev/null'")

shutdown = threading.Event()

threads = [
    threading.Thread(target=dhcp_listener, args=(67, boot_url, shutdown, server_ip), daemon=True),
    threading.Thread(target=_tftp_listener, args=(69, boot_dir, shutdown), daemon=True),
    threading.Thread(target=_http_server, args=(http_port, boot_dir, shutdown), daemon=True),
]

for t in threads:
    t.start()

print("[*] All servers started")
print(f"[*] DHCP  : UDP 67  (boot: {boot_url})")
print(f"[*] TFTP  : UDP 69")
print(f"[*] HTTP  : TCP {http_port}")
print(f"[*] Server: {server_ip}")

try:
    shutdown.wait()
except KeyboardInterrupt:
    shutdown.set()
