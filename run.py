"""Uruchamia panel w przeglądarce: python run.py

Nie wymaga instalacji pakietu ani aktywacji środowiska wirtualnego.
"""

import socket
import sys
import threading
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from alert_scanner.web import main  # noqa: E402


def _find_free_port(start: int = 8000, limit: int = 20) -> int:
    for port in range(start, start + limit):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start


if __name__ == "__main__":
    port = _find_free_port()
    threading.Timer(1.0, webbrowser.open, args=(f"http://127.0.0.1:{port}",)).start()
    raise SystemExit(main(["--port", str(port), *sys.argv[1:]]))

