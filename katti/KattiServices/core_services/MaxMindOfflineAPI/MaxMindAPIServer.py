import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Any

from katti.KattiServices.core_services.MaxMindOfflineAPI.MaxMindOfflineDBHolder import MaxMindDBHolder, set_key

from katti.DataBaseStuff.MongoengineDocuments.Scanner.MaxMindOffline import MaxMindOfflineDB
from katti.KattiServices.BaseKattiSerivce import BaseKattiService

DB_HOLDER: MaxMindDBHolder | None = None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_POST(self):
        global DB_HOLDER
        result = {}
        try:
            match self.path:
                case '/asn':
                    content_length = int(self.headers['Content-Length'])
                    if content_length > 0:
                        data = json.loads((self.rfile.read(content_length).decode('utf-8')))
                        result = DB_HOLDER.get_asn_for_ips(data['ips'])
                case '/country':
                    content_length = int(self.headers['Content-Length'])
                    if content_length > 0:
                        data = json.loads((self.rfile.read(content_length).decode('utf-8')))
                        result = DB_HOLDER.get_country_for_ips(data['ips'])
                case '/city':
                    content_length = int(self.headers['Content-Length'])
                    if content_length > 0:
                        data = json.loads((self.rfile.read(content_length).decode('utf-8')))
                        result = DB_HOLDER.get_city_for_ips(data['ips'])
                case '/status':
                    pass
        except Exception as e:
            self.send_response(402, )
            self.wfile.write(str(e).encode())
            self.end_headers()
        else:
            self.send_response(200,)
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def create_server(port):
    server = ThreadedHTTPServer(('0.0.0.0', port), Handler)
    server.serve_forever()


class APIService(BaseKattiService):
    def _next_control_round(self):
        time.sleep(15)

    def prepare_service(self):
        global DB_HOLDER
        max_mind_scanner = MaxMindOfflineDB.objects.get()
        set_key(key=max_mind_scanner.license_key)
        DB_HOLDER = MaxMindDBHolder()
        self._server = threading.Thread(target=create_server, args=(max_mind_scanner.docker_port,))
        self._server.start()