"""HTTP server — streams boot payloads (kernel, initrd, ISOs) to iPXE clients."""

import threading, traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path


CHUNK_SIZE = 256 * 1024

MIME_TYPES = {
    ".kernel": "application/octet-stream",
    ".bzImage": "application/octet-stream",
    ".vmlinuz": "application/octet-stream",
    ".initrd": "application/octet-stream",
    ".img": "application/octet-stream",
    ".squashfs": "application/octet-stream",
    ".iso": "application/x-iso9660-image",
    ".kpxe": "application/octet-stream",
    ".efi": "application/octet-stream",
    ".pxe": "application/octet-stream",
    ".cfg": "text/plain",
    ".conf": "text/plain",
}


class BootHTTPHandler(BaseHTTPRequestHandler):
    """Serves boot assets from the configured boot directory."""

    boot_root: Path = Path(".")
    extra_paths: list[Path] = []

    def do_GET(self) -> None:
        path = self.path.lstrip("/")
        if not path:
            self.send_error(404)
            return

        full_path = (self.boot_root / path).resolve()
        boot_root_resolved = self.boot_root.resolve()
        allowed = str(full_path).startswith(str(boot_root_resolved))
        if not allowed:
            for extra in self.extra_paths:
                extra_resolved = extra.resolve()
                if str(full_path).startswith(str(extra_resolved)):
                    allowed = True
                    break
        if not allowed:
            self.send_error(403)
            return

        if not full_path.exists() or full_path.is_dir():
            self.send_error(404)
            return

        try:
            file_size = full_path.stat().st_size
            ext = full_path.suffix.lower()
            content_type = MIME_TYPES.get(ext, "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(file_size))
            self.send_header("Connection", "close")
            self.end_headers()
            with open(full_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except Exception as e:
            print(f"[!] HTTP: error serving {path}: {e}")
            traceback.print_exc()

    def log_message(self, format: str, *args: object) -> None:
        print(f"[+] HTTP {args[0]}")


def _http_server(port: int, boot_root: Path, shutdown: threading.Event) -> None:
    """Start the HTTP file server."""
    try:
        BootHTTPHandler.boot_root = boot_root
        server = HTTPServer(("0.0.0.0", port), BootHTTPHandler)
        print(f"[*] HTTP listening on TCP {port} (root: {boot_root})")
        server.timeout = 1.0
        while not shutdown.is_set():
            server.handle_request()
    except Exception:
        traceback.print_exc()
