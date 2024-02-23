import copy
import datetime
import sys
import traceback
from abc import abstractmethod
from bson import ObjectId
from mongoengine import NotUniqueError
from pydantic import Field
from pydantic.dataclasses import dataclass
from pymongo import InsertOne
from pymongo.errors import BulkWriteError
from katti.CeleryBeatMongo.models import PeriodicTask, Crontab
from katti.DataBaseStuff.MongoengineDocuments.Feeds.BaseFeedDocuments import BaseFeedDB
import celery
from katti.DataFeeds import FeedRegistryBase
from katti.RedisCacheLayer.RedisMongoCache import RedisMongoCache


@dataclass
class Feed:
    crontab: dict
    active: bool
    field_name_plus: str = ''
    feed_args: dict = Field(default_factory=dict)


@dataclass
class FeedInitConFig:
    name: str
    description: str
    feed_type: str
    feeds: list[Feed]
    main_args: dict = Field(default_factory=dict)


class BaseFeed(metaclass=FeedRegistryBase):
    def __init__(self, feed_id: ObjectId, logger, task: celery.Task, model_name):
        self.feed_db = BaseFeedDB.objects.get(id=feed_id)
        self.redis_cache = RedisMongoCache()
        self.logger = logger
        self.counter = 0
        self._feed_entries = []
        self.bulk_ordered = False
        self._task = task
        self._model_name = model_name
        self._retry_settings = {'countdown': 3600}        #For options see: https://docs.celeryq.dev/en/stable/reference/celery.app.task.html#celery.app.task.Task.retry

    def data_test(self):
        pass
    #TODO: abstractmethod: After every run check integrity of feed data

    @abstractmethod
    def produce_feed(self):
        pass

    @property
    @abstractmethod
    def entry_cls(self):
        pass

    @staticmethod
    @abstractmethod
    def get_feed_type() -> str:
        pass

    @classmethod
    @abstractmethod
    def add_feed_to_system_stuff(cls, config: dict):
        pass

    @classmethod
    def add_feed_to_system(cls, config: FeedInitConFig):
        """This is NOT! an update function. Use the function only for the first init!"""
        args_for_build = {'name': config.name, 'description': config.description, 'feed_type': config.feed_type}
        args_for_build.update(config.main_args)

        for sub_feed in config.feeds:
            args_clone = copy.deepcopy(args_for_build)
            if sub_feed.field_name_plus:
                args_clone['name'] = f'{args_clone["name"]}_{sub_feed.field_name_plus}'
            args_clone.update(sub_feed.feed_args)
            feed_db = cls.add_feed_to_system_stuff(args_clone)
            periodic_task = PeriodicTask(name=args_clone['name'], task='katti.CeleryApps.DataFeedTasks.execute_feed',
                                         enabled=sub_feed.active,
                                         run_immediately=True,
                                         crontab=Crontab(**sub_feed.crontab))
            as_son = feed_db.to_mongo()
            del as_son['name']
            del as_son['_cls']
            try:
                feed_db.save()
            except NotUniqueError:
                print(f'NotUniqueError, {feed_db.name}')
                return
            feed_db.ensure_indexes()
            periodic_task.args = [feed_db.id, cls.__name__]
            periodic_task.save()

        cls.ensure_sub_indexes()

    @staticmethod
    def ensure_sub_indexes():
        pass

    def after_stuff_error(self):
        pass

    def after_stuff_success(self):
        pass



    @property
    def update_or_insert(self) -> int:
        """"" 1 = update
                2 = insert
                Overwrite for behaviour change"""
        return 1

    @property
    def ignore_bulk_write_errors(self) -> bool:
        """""    Overwrite for behaviour change"""
        return True

    @property
    def entry_with_feed_id(self) -> bool:
        return True

    @property
    def entry_with_validation(self) -> bool:
        return True

    def retry_feed_execution(self):
        if not self._task:
            self.logger.debug(f'DEBUG mode, no retry:) ')
        else:
            self.logger.info(f'Retry feed execution.')
            self._task.retry(args=(self.feed_db.id, self._model_name), **self._retry_settings)

    def handle_bulk_write_error(self, error: BulkWriteError):
        self._error = True
        self.logger.error(traceback.format_exception(*sys.exc_info()))

    def after_feed_entries_update(self):
        pass

    def fetch_feed_data(self):
        self.logger.debug('Start fetching feed data')
        self.produce_feed()
        self._save_feed_entries_update()
        self.logger.info(f'Finished fetching data. Counter: {self.counter}')

    def _save_feed_entries_update(self):
        self._entry_collection = self.entry_cls()._get_collection()
        if len(self._feed_entries) > 0:
            try:
                self._entry_collection.bulk_write(self._feed_entries, ordered=self.bulk_ordered)
            except BulkWriteError as error:
                try:
                    self.handle_bulk_write_error(error)
                except Exception:
                    self._error = True
                    self.logger.error(traceback.format_exception(*sys.exc_info()))
            except Exception:
                self._error = True
                self.logger.error(traceback.format_exception(*sys.exc_info()))
            finally:
                self._feed_entries = []

    def insert_new_entry_into_list(self, new_entry):
        if not new_entry:
            return
        new_entry.katti_create = datetime.datetime.utcnow()
        new_entry.feed = self.feed_db if self.entry_with_feed_id else None
        if len(self._feed_entries) > 10000:
            self._save_feed_entries_update()
            self.after_feed_entries_update()
        try:
            if self.entry_with_validation:
                new_entry.validate()
            if self.update_or_insert == 1:
                x = new_entry.get_update_one()
                if isinstance(x, list):
                    self._feed_entries.extend(x)
                else:
                    self._feed_entries.append(x)
            else:
                self._feed_entries.append(InsertOne(new_entry.to_mongo()))
            self.counter += 1
        except Exception:
            self._error = True
            self.logger.error(traceback.format_exception(*sys.exc_info()))




