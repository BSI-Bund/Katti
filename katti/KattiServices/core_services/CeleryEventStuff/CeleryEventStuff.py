import datetime
import logging
import threading
import time
from queue import Queue, Empty
from bson import ObjectId
from mongoengine import get_db
from pymongo import UpdateOne
from katti.CeleryApps.KattiApp import katti_app
from katti.CeleryApps.TriggerTasks import receive_new_feed_trigger
from katti.DataBaseStuff.ConnectDisconnect import connect_to_database
from katti.KattiServices.BaseKattiSerivce import BaseKattiService
from katti.KattiServices.DockerHealthCheckHTTPServer import DockerHealthCheckThread


# Inspired by: https://vilya.pl/handling-celery-events/

class CeleryEventStuff(BaseKattiService):
    def prepare_service(self):
        self._update_queue = Queue()
        self._stop_event = threading.Event()

        self._helper_thread = threading.Thread(target=heartbeat_timer, args=(self.docker_health_api_server,
                                                                             self._stop_event))
        self._helper_thread.start()

        self._save_thread = threading.Thread(target=event_to_database, args=(self._update_queue, self._stop_event))
        self._save_thread.start()
        self._state = katti_app.events.State()

    def shutdown(self):
        self._stop_event.set()
        start = datetime.datetime.utcnow()
        try:
            self._save_thread.join(timeout=10)
            x = (datetime.datetime.utcnow() - start).total_seconds()
            if x > 0:
                self._helper_thread.join(timeout=10 - x)
        except Exception:
            pass

    def _next_control_round(self):
        with katti_app.connection() as connection:
            recv = katti_app.events.Receiver(connection, handlers={
                'task-sent': self._on_task_sent,
                'task-received': self._on_task_received,
                'task-started': self._on_task_started,
                'task-succeeded': self._on_task_succeeded,
                'task-failed': self._on_task_failed,
                'task-rejected': self._on_task_rejected,
                'task-revoked': self._on_task_revoked,
                'task-retried': self._on_task_retried,
                'katti-feed-trigger': self.feed_trigger,
                'katti-telegr-trigger': self.telegram_trigger
            })
            # recv.consume() => blocking
            i = 0
            for _ in recv.itercapture(limit=None, timeout=self.env_vars.get('receiver_timeout', 20)):
                i += 1
               # print(f'counter: {i}')
                if self._stop_event.is_set():
                    break

    def feed_trigger(self, event):
        receive_new_feed_trigger.apply_async(args=(ObjectId(event['feed_id']), event['status']))

    def telegram_trigger(self, event):
        pass

    def _to_datetime(self, timestamp):
        return datetime.datetime.fromtimestamp(timestamp) if timestamp is not None else None

    def _new_event(handler):
        def wrapper(self, event):
            self._state.event(event)
            task = self._state.tasks.get(event['uuid'])
            handler(self, event, task)

        return wrapper

    def _get_task_children(self, task):
        return [f'{child.uuid}' for child in task.children]

    @_new_event
    def _on_task_sent(self, event, task):
        self._update_queue.put(UpdateOne(
            {'task_id': task.uuid}, {'$setOnInsert': {'name': task.name, 'state': task.state,
                                                      'sent': self._to_datetime(task.sent),
                                                      'root_id': f'{task.root_id}',
                                                      'parent_id': f'{task.parent_id}'}}, upsert=True))

    @_new_event
    def _on_task_received(self, event, task):
        self._update_queue.put(UpdateOne({'task_id': task.uuid},
                                         {'$set': {'state': task.state,
                                                   'received': self._to_datetime(task.received),
                                                   'worker': f'{task.worker}',
                                                   'client': task.client,
                                                   'exchange': task.exchange,
                                                   'routing_key': task.routing_key,
                                                   'timestamp': self._to_datetime(task.timestamp)},
                                          '$addToSet': {'children': self._get_task_children(task)}}))

    @_new_event
    def _on_task_started(self, event, task):
        self._update_queue.put(UpdateOne({'task_id': task.uuid},
                                         {'$set': {'state': task.state,
                                                   'started': self._to_datetime(task.started)}}))

    @_new_event
    def _on_task_succeeded(self, event, task):
        self._update_queue.put(UpdateOne({'task_id': task.uuid},
                                         {'$set': {'state': task.state,
                                                   'succeeded': self._to_datetime(task.succeeded),
                                                   'runtime': task.runtime,
                                                   'retries': task.retries},
                                          '$addToSet': {'children': self._get_task_children(task)}}))

    @_new_event
    def _on_task_failed(self, event, task):
        self._update_queue.put(self._standart_fail(task))

    @_new_event
    def _on_task_rejected(self, event, task):
        self._update_queue.put(self._standart_fail(task, **{'rejected': self._to_datetime(task.rejected)}))

    @_new_event
    def _on_task_revoked(self, event, task):
        self._update_queue.put(self._standart_fail(task, **{'revoked': self._to_datetime(task.revoked)}))

    @_new_event
    def _on_task_retried(self, event, task):
        self._update_queue.put(UpdateOne({'task_id': task.uuid},
                                         {'$set': {'state': task.state},
                                          '$push': {'retries_times': self._to_datetime(task.retried)},
                                          '$addToSet': {'children': self._get_task_children(task)}}))

    def _standart_fail(self, task, **kwargs):
        x = {'state': task.state,
             'failed': self._to_datetime(task.failed),
             'runtime': task.runtime,
             'exception': f'{task.exception}',
             'retries': task.retries,
             'traceback': f'{task.traceback}'}
        x.update(kwargs)
        return UpdateOne({'task_id': task.uuid}, {'$set': x,
                                                  '$addToSet': {'children': self._get_task_children(task)}})


def heartbeat_timer(heartbeat_api_server: DockerHealthCheckThread, stop: threading.Event):
    while True and not stop.is_set():
        time.sleep(30)
        heartbeat_api_server.set_status('ok')


def event_to_database(queue: Queue, stop_event):
    db = get_db('Katti')
    bulk_ops = []
    last_op = datetime.datetime.utcnow()
    while not stop_event.is_set():
        try:
            next_op = queue.get(timeout=5)
            bulk_ops.append(next_op)
        except Empty:
            pass
        finally:
            if len(bulk_ops) > 0 and (len(bulk_ops) > 0 or (datetime.datetime.utcnow() - last_op).total_seconds() > 10):
                db['celery_events'].bulk_write(bulk_ops)
                bulk_ops = []
                last_op = datetime.datetime.utcnow()
    if len(bulk_ops) > 0:
        db['celery_events'].bulk_write(bulk_ops)


if __name__ == '__main__':
    connect_to_database()
    x = CeleryEventStuff(env_vars={'service_type': 'celery_events', 'log_level': logging.DEBUG})
    x.run()
