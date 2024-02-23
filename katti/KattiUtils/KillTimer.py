import datetime
import threading


class KillTimer:
    def __init__(self, timeout_func, logger):
        self._timeout_func = timeout_func
        self._logger = logger
        self._timer = None
        self._start_time = None
        self._timeout = None

    def start(self, timeout=30):
        if self._timer:
            pass
        else:
            self._timeout = timeout
            self._time_left = None
            self._start(timeout)

    def _start(self, timeout):
        self._start_time = datetime.datetime.now()
        self._timer = threading.Timer(interval=timeout, function=self._timeout_func)
        self._timer.start()

    def make_a_break(self):
        if not self._timer:
            self.start()
        else:
            self._time_left = self._timeout - ((datetime.datetime.now() - self._start_time).seconds)
            self._timer.cancel()
            self._timer = None

    def start_again_after_break(self):
        if not self._time_left:
            self.start()
        self._start(self._time_left)

    def stop(self):
        if self._timer:
            self._timer.cancel()
            self._timer = None