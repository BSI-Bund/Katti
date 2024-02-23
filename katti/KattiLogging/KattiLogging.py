import os.path
import sys
from katti.KattiLogging.LogDocument import CommonLogDocument, BaseLogDocument
from katti.KattiLogging.MongoFormatter import MongoFormatter
import logging
import atexit
import threading


FLUSHING_TIME = 5
BUFFER_SIZE = 40
EARLY_FLUSH_LEVEL = logging.ERROR


class MongoHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET, **kwargs):
        super().__init__(level)
        atexit.register(self.destroy)
        self._buffer_lock = threading.RLock()
        self.buffer = []

        def call_repeatedly(interval, func, *args):
            stopped = threading.Event()

            def loop():
                while not stopped.wait(interval):
                    func(*args)

            timer_thread = threading.Thread(target=loop)
            timer_thread.daemon = True
            timer_thread.start()
            return stopped.set, timer_thread

        self._timer_stopper, self.buffer_timer_thread = call_repeatedly(5, self.flush_to_mongo)

    def buffer_lock_acquire(self):
        if self._buffer_lock:
            self._buffer_lock.acquire()

    def buffer_lock_release(self):
        if self._buffer_lock:
            self._buffer_lock.release()

    def add_to_buffer(self, record):
        self.buffer_lock_acquire()
        self.buffer.append(self.format(record))
        self.buffer_lock_release()

    def flush_to_mongo(self):
        if len(self.buffer) > 0:
            self.buffer_lock_acquire()
            try:
                BaseLogDocument.objects.insert(self.buffer)
                self.empty_buffer()

            except Exception as e:
                pass
            finally:
                self.buffer_lock_release()

    def empty_buffer(self):
        self.buffer = []

    def destroy(self):
        if self._timer_stopper:
            self._timer_stopper()
        self.flush_to_mongo()
        self.close()

    def emit(self, record):
        global EARLY_FLUSH_LEVEL, BUFFER_SIZE
        try:
            self.add_to_buffer(record)
            if len(self.buffer) >= BUFFER_SIZE or record.levelno >= EARLY_FLUSH_LEVEL:
                self.flush_to_mongo()
        except Exception as e:
            with(os.path.expanduser('~/katti_logs.log'), 'a') as file:
                file.write(f'{record}\n')


def setup_logger(name: str, level: int, log_class=CommonLogDocument, docker_celery_task_id=None) -> logging.Logger:
    handler = MongoHandler(level)
    handler.setFormatter(MongoFormatter(docker_celery_task_id=docker_celery_task_id, log_class=log_class))
    logger = logging.getLogger(name=name)
    logger.setLevel(level)
    logger.addHandler(handler)
   # if os.path.exists(os.path.expanduser('~/home')):
   #     logger.addHandler(logging.StreamHandler(sys.stdout))
    return logger

