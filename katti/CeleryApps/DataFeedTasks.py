import logging
import sys
import traceback
from katti.DataBaseStuff.MongoengineDocuments.StatisticDocuments.FeedTaskStatistics import FeedTaskStatistics
from bson import ObjectId
from katti.CeleryApps.KattiApp import katti_app
from katti.DataFeeds import load_all_feed_cls, FeedRegistryBase
import celery
from celery import exceptions


class BaseTaskWithRetry(celery.Task):
    max_retries = 3
    retry_backoff = True
    default_retry_delay = 10 * 60


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def execute_feed(self, feed_id: ObjectId, model_name: str, **kwargs):
    logger = logging.getLogger(f'{model_name}<:>{feed_id}')
    logger.debug(f'Feed model {model_name}')
    stats = FeedTaskStatistics.get_task_with_times(task_id=self.request.id, **{'feed_id': feed_id})
    status = 'UNKNOWN'
    try:
        load_all_feed_cls()
        feed_cls = FeedRegistryBase.get_registry()[model_name]
        feed = feed_cls(feed_id=feed_id, logger=logger, task=self, model_name=model_name)
        feed.fetch_feed_data()
    except exceptions.Retry:
        status = 'RETRY'
        raise
    except Exception:
        stats.error = True
        logger.error(traceback.format_exception(*sys.exc_info()))
        feed.after_stuff_error()
        status = 'ERROR'
        raise
    else:
        feed.after_stuff_success()
        stats.entries_counter = feed.counter
        status = 'SUCCESS'
        logger.debug(f'Save updated feed model')
    finally:
        self.send_event(type_='katti-feed-trigger', **{'feed_id': str(feed_id),
                                                      'status': status})
        stats.stop_and_save()
