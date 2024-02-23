import time

from bson import ObjectId
from celery import Task

from katti.CeleryApps.KattiApp import katti_app
from katti.KattiUtils.Exceptions.ScannerExceptions import LongTermRetryException


@katti_app.task(bind=True)
def send_trigger_event(self, test_feed_id: ObjectId, status: str):
    self.send_event(type_='katti-feed-trigger', **{'feed_id': str(test_feed_id),
                                                   'status': status})

x = Task()

@katti_app.task(bind=True, throws=(LongTermRetryException))
def only_start_a_task(self, *args, **kwargs):
    raise LongTermRetryException()
    print(self.max_retries)
    self.override_max_retries = 5
    print(self.max_retries)
    if kwargs.get('sleep'):
        time.sleep(kwargs.get('sleep'))
    if kwargs.get('ex'):
        raise Exception('TEST')
    if kwargs.get('retry'):
        time.sleep(1)
        self.retry(countdown=1)
    print(f'args: {args}\n kwargs: {kwargs}')