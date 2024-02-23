import datetime
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Any


LOCK: threading.Lock = threading.Lock()
LAST_HEARTBET: datetime.datetime = datetime.datetime.utcnow()
STATUS: str = 'unknown'


class Handler(BaseHTTPRequestHandler):

    def log_message(self, format: str, *args: Any) -> None:
        pass


    def do_GET(self):
        global LOCK, LAST_HEARTBET, STATUS
        match self.path:
            case '/status':
                with LOCK:
                    match STATUS:
                        case 'unknown':
                            pass
                        case 'ok' if (datetime.datetime.utcnow() - LAST_HEARTBET).total_seconds() <= 5*60:
                            pass
                        case _:
                            self.send_response(code=403)
                            self.end_headers()
                            return
                    self.send_response(code=200)
                    self.end_headers()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


class DockerHealthCheckThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self._server: ThreadedHTTPServer | None = None

    def run(self):
        self._server = ThreadedHTTPServer(('127.0.0.1', 7070), Handler)
        self._server.serve_forever()

    def set_status(self, new_status):
        global LOCK, LAST_HEARTBET, STATUS
        with LOCK:
            LAST_HEARTBET = datetime.datetime.utcnow()
            STATUS = new_status


if __name__ == '__main__':
    thread_server = DockerHealthCheckThread()
    thread_server.start()
    thread_server.join()