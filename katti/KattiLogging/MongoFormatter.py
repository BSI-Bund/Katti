import datetime
import logging
import platform
import typing
from celery._state import get_current_task
from katti.KattiLogging.LogDocument import HeartBeatLogs, BaseLogDocument


class MongoFormatter(logging.Formatter):
    DEFAULT_PROPERTIES = logging.LogRecord(
        '', '', '', '', '', '', '', '').__dict__.keys()

    def __init__(self, log_class, docker_celery_task_id=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            self.get_current_task = get_current_task
        except ImportError:
            self.get_current_task = lambda: 'No current task'
        self._log_class = log_class
        self._kwargs = kwargs
        self._docker_celery_task_id = docker_celery_task_id

    def format(self, record):
        if record.funcName == 'heartbeat_tick':
            return self._generate_hearbeat_tick_log(record)
        else:
            return self._generate_normale_log(record)

    def _generate_hearbeat_tick_log(self, record) -> HeartBeatLogs:
        new_log = HeartBeatLogs(logger_name=record.name,
                                level=record.levelname,
                                thread=record.thread,
                                thread_name=record.threadName,
                                message=record.getMessage(),
                                file_name=record.filename,
                                module=record.module,
                                method=record.funcName,
                                line_number=record.lineno,
                                machine_node=platform.node(),
                                timestamp=datetime.datetime.utcnow())
        return new_log

    def _generate_normale_log(self, record) -> typing.Union[BaseLogDocument]:
        if len(self.DEFAULT_PROPERTIES) != len(record.__dict__):
            contextual_extra = set(record.__dict__).difference(
                set(self.DEFAULT_PROPERTIES))
            if contextual_extra and 'katti_extra' in contextual_extra:
                pass
        new_log = self._log_class(logger_name=record.name,
                                  level=record.levelname,
                                  thread=record.thread,
                                  thread_name=record.threadName,
                                  message=record.getMessage(),
                                  file_name=record.filename,
                                  module=record.module,
                                  method=record.funcName,
                                  line_number=record.lineno,
                                  machine_node=platform.node(),
                                  timestamp=datetime.datetime.utcnow())
        task = self.get_current_task()
        if task:
            try:
                new_log.task_id = task.request.id
                new_log.task_name = task.name
            except Exception:
                pass
        if self._docker_celery_task_id:
            new_log.docker_celery_task_id = self._docker_celery_task_id

        # Standard document decorated with exception info
        if record.exc_info is not None:
            new_log.exception = {
                'message': str(record.exc_info[1]),
                'code': 0,
                'stackTrace': self.formatException(record.exc_info)
            }

        return new_log
