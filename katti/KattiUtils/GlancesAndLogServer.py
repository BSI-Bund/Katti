import datetime
import json
import platform
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any
from mongoengine import get_db, DateTimeField, EmbeddedDocument, StringField, \
    EmbeddedDocumentField
from pymongo.errors import CollectionInvalid
from katti.DataBaseStuff.ConnectDisconnect import connect_to_database, disconnect_to_database
from katti.DataBaseStuff.MongoengineDocuments.StatisticDocuments.TaskBaseStatistics import BaseStatistics

#TODO: Kein Buffer bei den Logs oder den Datapoints

VM_NAME = platform.node()


class GlancesDataPoint(BaseStatistics):
    meta = {'collection': 'glances',
            'indexes': [{'fields': ['metadata.machine_name']}]}
    class Meta(EmbeddedDocument):
        machine_name = StringField()
    create = DateTimeField(default=datetime.datetime.utcnow())
    metadata = EmbeddedDocumentField(Meta)

    @staticmethod
    def create_time_series_collection():
        try:
            get_db(alias='Statistics').create_collection('glances', timeseries={'timeField': 'create', 'metaField': 'metadata'})
        except CollectionInvalid:
            print('Collection already exists')


class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        if content_length > 0:
            data = self.rfile.read(content_length)
            match self.path:
                case '/logs':
                    print(json.loads(data.decode('utf-8')))
                case _:
                    new_datapoint = GlancesDataPoint(**json.loads(data.decode('utf-8')))
                    new_datapoint.metadata = GlancesDataPoint.Meta(machine_name=VM_NAME)
                    new_datapoint.save()
        self.send_response(200)
        self.end_headers()


def start_glances(stop_event):
    p = subprocess.Popen(['glances', '-q', '--export', 'restful'])
    while not stop_event.is_set():
        time.sleep(0.5)
    p.kill()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


if __name__ == '__main__':
    connect_to_database()
    GlancesDataPoint.create_time_series_collection()
    server = ThreadedHTTPServer(("", 6789), RequestHandler)
    stop_event = threading.Event()
    x = threading.Thread(target=start_glances, args=(stop_event,))
    x.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        stop_event.set()
        server.server_close()
        disconnect_to_database()


