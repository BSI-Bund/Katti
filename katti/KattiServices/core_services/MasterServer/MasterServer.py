import copy
import json
import pickle
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any
from cryptography.fernet import Fernet
from katti.KattiLogging.KattiLogging import setup_logger


mongodb_config = {}
redis_config = {}
celery_config = {}

class Handler(BaseHTTPRequestHandler):

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self):
        global master_config
        match self.path:
            case '/mongodb_config':
                data = copy.deepcopy(mongodb_config)
            case '/redis_config':
                data = copy.deepcopy(redis_config)
            case '/celery_config':
                data = copy.deepcopy(celery_config)
            case '/infrastructure':
                pass
            case '/status':
                self.send_response(code=200)
                self.end_headers()
                return
            case _:
                self.send_response(403)
                self.end_headers()
                return

        self.send_response(200)
        self.send_header('Content-type', 'application/python-pickle')
        self.send_header('Content-length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def start_http_server():
    server = ThreadedHTTPServer(('0.0.0.0', 8585), Handler)
    server.serve_forever()


class MasterServer:

    def __init__(self, env_vars):
        self.logger = setup_logger(name=env_vars['service_type'], level=env_vars['log_level'])
        self.env_vars = env_vars
        self._master_config = {'key': env_vars['master_key'], 'base_url': env_vars['master_base_url']}
        self._init()

    def _init(self):
        global mongodb_config, redis_config, celery_config

        f = Fernet(self._master_config['key'].encode())
        mongodb_config = f.encrypt(pickle.dumps({'katti': self.env_vars['mongo_uri']}))
        redis_config = f.encrypt(pickle.dumps(json.loads(self.env_vars['redis_json_str'])))
        celery_config = f.encrypt(pickle.dumps(json.loads(self.env_vars['celery_str'])))

    def start(self):
        self.server = ThreadedHTTPServer(('0.0.0.0', 8585), Handler)
        self.server.serve_forever()
