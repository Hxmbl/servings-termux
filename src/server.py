"""Thread orchestration — launches all PXE boot servers concurrently.

Root mode: full DHCP server on port 67, replaces Android's dnsmasq (default).
Non-root mode: ProxyDHCP on port 4011, limited (Android's DHCP doesn't advertise PXE).

Root mode setup:
  su -c killall dnsmasq
  servings serve

Non-root (limited):
  servings serve --no-root
"""

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.proxydhcp import _proxydhcp_listener
from src.tftp import _tftp_listener
from src.http_server import _http_server
from src.boot_config import generate_boot_config


def serve(
    port: int = 67,
    tftp_port: int = 69,
    http_port: int = 8080,
    boot_dir: str = ".",
    root_mode: bool = True,
    server_ip: str = "192.168.42.129",
    boot_file: str = "undionly.kpxe",
) -> None:
    """Start all PXE boot servers concurrently.

    Root mode (default): uses port 67 for full DHCP (needs su to bind).
    Non-root mode: uses port 4011 for ProxyDHCP (limited without root).

    Port notes:
        - DHCP: 67 (root) or 4011 (non-root)
        - TFTP: 69 (root) or 6969 (non-root)
        - HTTP: 8080 is standard for alt HTTP; iPXE hits this for heavy payloads
    """
    root = Path(boot_dir).resolve()
    if not root.exists():
        print(f"[!] Boot directory does not exist: {root}")
        raise SystemExit(1)

    try:
        generate_boot_config(root)
    except OSError as e:
        print(f"[!] Could not generate boot.cfg: {e}")

    # Determine which ports to use based on root mode
    dhcp_port = 67 if root_mode else port
    tftp_actual = 69 if root_mode else tftp_port

    print()
    print("=" * 55)
    print("  Servings PXE Boot Server")
    print("=" * 55)
    if root_mode:
        print("  MODE      : ROOT — full DHCP server on port 67")
        print("  WARNING   : Kill Android's dnsmasq first:")
        print("              su -c killall dnsmasq")
    else:
        print("  MODE      : non-root — ProxyDHCP only (limited)")
        print("  WARNING   : Android's DHCP doesn't advertise PXE options.")
        print("              The PC may not discover this server.")
    print(f"  DHCP      : UDP {dhcp_port}")
    print(f"  TFTP      : UDP {tftp_actual}")
    print(f"  HTTP      : TCP {http_port}")
    print(f"  Boot dir  : {root}")
    print(f"  Boot file : {boot_file}")
    print(f"  Server IP : {server_ip}")
    print("=" * 55)
    print()

    shutdown = threading.Event()
    executor = ThreadPoolExecutor(max_workers=6)

    if root_mode:
        # Root mode: full DHCP server handles both IP assignment and PXE
        from src.dhcp_server import dhcp_listener
        executor.submit(dhcp_listener, dhcp_port, boot_file, shutdown, server_ip)
    else:
        # Non-root: ProxyDHCP only — Android's DHCP handles IP assignment
        executor.submit(_proxydhcp_listener, dhcp_port, shutdown)

    executor.submit(_tftp_listener, tftp_actual, root, shutdown)
    executor.submit(_http_server, http_port, root, shutdown)

    try:
        while not shutdown.is_set():
            shutdown.wait(3600)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        shutdown.set()
        executor.shutdown(wait=True)
