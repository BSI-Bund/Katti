from __future__ import print_function
import datetime
import json
import threading
import time
from dataclasses import dataclass, field
from pymongo import InsertOne
from websocket import WebSocketApp


@dataclass
class ThreadData:
    stop_event: threading.Event = threading.Event()
    new_entries: list[InsertOne] = field(default_factory=list)
    X509LogEntry: bool = True
    PrecertLogEntry: bool = True
    lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    @property
    def entry_list_len(self) -> int:
        with self.lock:
            return len(self.new_entries)

    @property
    def is_x_509_log_entry(self) -> bool:
        with self.lock:
            return self.X509LogEntry

    @is_x_509_log_entry.setter
    def is_x_509_log_entry(self, new_value: bool):
        with self.lock:
            self.X509LogEntry = new_value

    @property
    def is_precert_log_entry(self) -> bool:
        with self.lock:
            return self.PrecertLogEntry

    @is_precert_log_entry.setter
    def is_precert_log_entry(self, new_value):
        with self.lock:
            self.PrecertLogEntry = new_value

    def add_new_entry(self, new_entry: InsertOne):
        with self.lock:
            self.new_entries.append(new_entry)


    def get_list_and_reset(self):
        with self.lock:
            x = self.new_entries
            self.new_entries = []
            return x


class Context(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class CertStreamClient(WebSocketApp):
    _context = Context()
    def __init__(self, url, logger, thread_data, skip_heartbeats=True):
        self.skip_heartbeats = skip_heartbeats
        self.logger = logger
        self.thread_data: ThreadData = thread_data
        super(CertStreamClient, self).__init__(
            url=url,
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=self._on_error,
        )

    def _on_open(self, _):
        pass
        #self.logger.info("Connection established to CertStream! Listening for events...")

    def _on_message(self, _, message):
        frame = json.loads(message)
        if frame.get('message_type', None) == "heartbeat" and self.skip_heartbeats:
            return

        if frame['message_type'] == "heartbeat":
            return
        if (frame['data']['update_type'] == 'X509LogEntry' and self.thread_data.is_x_509_log_entry) or (frame['data']['update_type'] == 'PrecertLogEntry' and self.thread_data.PrecertLogEntry):
            try:
                frame['data']['seen'] = datetime.datetime.fromtimestamp(frame['data']['seen'])
                frame['data']['leaf_cert']['not_after'] = datetime.datetime.fromtimestamp(
                    frame['data']['leaf_cert']['not_after'])
                frame['data']['leaf_cert']['not_before'] = datetime.datetime.fromtimestamp(
                    frame['data']['leaf_cert']['not_before'])
                frame['data']['leaf_cert']['signature_algorithm'] = (
                    frame['data']['leaf_cert']['signature_algorithm'].replace(' ', '')).split(',')
                self.thread_data.add_new_entry(InsertOne(frame['data']))
            except Exception:
                pass
        if self.thread_data.stop_event.is_set():
            self.close()

    def _on_error(self, _, ex):
        if type(ex) == KeyboardInterrupt:
            raise
        #self.logger.error("Error connecting to CertStream - {} - Sleeping for a few seconds and trying again...".format(ex))



def listen_for_events(url, logger, thread_data: ThreadData, skip_heartbeats=True, **kwargs):
    try:
        while True:
            c = CertStreamClient(url, skip_heartbeats=skip_heartbeats, logger=logger, thread_data=thread_data)
            c.run_forever(ping_interval=15, **kwargs)
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Kill command received, exiting!!")

