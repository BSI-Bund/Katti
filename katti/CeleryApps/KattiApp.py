import logging
import os
import sys
from kombu import Queue
from katti.CeleryApps.Routers import route_task
from katti.KattiLogging.LogDocument import CeleryLog
from katti.KattiLogging.MongoFormatter import MongoFormatter
from katti.KattiLogging.KattiLogging import MongoHandler
from billiard import context
from celery import Celery
import celery.signals
from katti.DataBaseStuff.ConnectDisconnect import connect_to_database, disconnect_to_database
from katti.KattiUtils.Configs.ConfigKeys import DEFAULT_SYSTEM_QUEUE_PRIO
from katti.KattiUtils.Configs.ConfigurationClass import CeleryConfig, DatabaseConfigs
from katti.RedisCacheLayer.RedisMongoCache import disconnect_redis

os.environ['FORKED_BY_MULTIPROCESSING'] = '1'
context._force_start_method('spawn')

redis_url = DatabaseConfigs.get_config().redis_url
celery_config = CeleryConfig.get_config()


queues = (Queue('scanning', 'scanning_exchange', routing_key='scanning', type='direct'),
          Queue('ssl_scanning', 'scanning_exchange', routing_key='ssl_scanning', type='direct'),
          Queue('periodic_tasks', 'periodic_exchange', routing_key='periodic', type='direct'),
          Queue('feeds', 'feeds_exchange', routing_key='feed', type='direct'),
          Queue('crawling_request', 'crawling_exchange', routing_key='crawling.request', type='direct'),
          Queue('crawler', 'crawling_exchange', routing_key='crawling.crawler', type='direct'),
          Queue('crawling_default', 'crawling_exchange', routing_key='crawling.default', type='direct'),
          Queue('telegram', 'telegram_exchange', routing_key='telegram', type='direct'),
          Queue('default', 'default_exchange', routing_key='default', type='direct'),
          Queue('fast_lane', 'fast_exchange', routing_key='fast', type='direct'),
          Queue('report_tasks', 'report_tasks', routing_key='reports', type='direct'),
          Queue('pdf_generation', 'pdf_generation', routing_key='pdf_generation', type='direct'))

katti_app = Celery('katti', broker=celery_config.broker, backend=f'{redis_url}/0', include=[
    'katti.CeleryApps.DataFeedTasks',
    'katti.CeleryApps.MailTasks',
    'katti.CeleryApps.CloudPickleTasks',
    'katti.CeleryApps.TestTasks',
    'katti.CeleryApps.IOCStuff',
    'katti.CeleryApps.Workflows.DNSToIPCeleryTasks',
'katti.CeleryApps.Common'])


@celery.signals.after_setup_logger.connect
def on_celery_setup_logging(logger, *args, **kwargs):
    connect_to_database()
    # import nest_asyncio
    # nest_asyncio.apply()
    if isinstance(logger.handlers[0], logging.StreamHandler):
        logger.removeHandler(logger.handlers[0])
    if len(logger.handlers) >= 1:
        return
    handler = MongoHandler()
    handler.setFormatter(MongoFormatter(log_class=CeleryLog))
    logger.addHandler(handler)
    if os.path.exists(os.path.expanduser('~/home')):
        logger.addHandler(logging.StreamHandler(sys.stdout))


@celery.signals.worker_process_shutdown.connect
def on_process_down(**kwargs):
    disconnect_to_database()
    disconnect_redis()


@celery.signals.worker_shutdown.connect
def on_worker_shutdown(**kwargs):
    pass


katti_app.conf.task_queues = queues
katti_app.conf.task_routes = (route_task,)
katti_app.conf.task_queue_max_priority = 10
katti_app.conf.task_default_priority = DEFAULT_SYSTEM_QUEUE_PRIO
katti_app.conf.task_send_sent_event = True

katti_app.conf.task_serializer = celery_config.task_serializer
katti_app.conf.result_serializer = celery_config.result_serializer
katti_app.conf.accept_content = celery_config.accept_content
