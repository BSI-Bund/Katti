import datetime
import hashlib
import logging
import pickle
import sys
import time
import traceback
import typing
from abc import abstractmethod, ABC
from dataclasses import InitVar
from random import randint
from celery import Task
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation
from katti.KattiUtils.Exceptions.CommonExtensions import ExtremeFailure
from mongoengine import get_db, DoesNotExist, NotUniqueError
from pydantic import Field, field_validator
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.Tag import MetaData, Ownership
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.TimeLord import TimeLord
from katti.KattiUtils.Exceptions.ScannerExceptions import OfflineModeNoResult, RetryException, APIErrorException, \
    LongTermRetryException
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.Scanner import ScannerRegistryBase
from katti.Scanner.QuotaMechanic import QuotaMechanic, MinuteBlockException, DayBlockException, QMinute, QDay, QuotaUserAPI
import katti.redis_lock as redis_lock
from bson import ObjectId, SON
from katti.RedisCacheLayer.RedisMongoCache import RedisMongoCache
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument, \
    BaseScanningRequests, ErrorParking


@dataclass(config=PydanticConfig)
class OOI(ABC):
    raw_ooi: typing.Any

    @property
    def ooi(self):
        return str(self.raw_ooi)


@dataclass
class Backpropagation:
    collection: str
    id_ooi_mapping: dict
    field_name: str



@dataclass
class InitScanner_config:
    scanner_type: str
    name: str
    default: bool
    args: dict | None = Field(default_factory=dict)

    @field_validator('args')
    def args_validator(cls, value):
        if not value:
            return {}
        return value


@dataclass(config=PydanticConfig)
class BaseScanningRequestForScannerObject(ABC):
    scanner_id: ObjectId
    oois: list[OOI]
    ownership_obj: InitVar[Ownership]
    meta_data_obj: InitVar[MetaData, None] = None
    ownership_as_son: SON = Field(default=None)
    meta_data_as_son: SON | None = Field(default=None)
    time_valid_response: int = Field(qe=0, default=3600)
    offline: bool = False
    quota_exception_day_retry: bool = True
    max_day_retries: int = 7
    quota_exception_minute_retry: bool = True
    api_request: bool = False

    long_term_retry_parent_task: str | None = None

    backwards_propagation: list[Backpropagation] | None = Field(default=None)

    def __post_init__(self, ownership_obj, meta_data_obj):
        if meta_data_obj:
            self.meta_data_as_son = meta_data_obj.to_mongo()
        self.ownership_as_son = ownership_obj.to_mongo()
        self._own_post_init()

    @classmethod
    def build_request(cls, raw_oois: list[typing.Any], ownership: Ownership, meta_data: MetaData | None, time_valid_response: int, scanner_id: ObjectId,
                      backwards_propagation: list[Backpropagation] | None = None,
                      offline_mode: bool = False, **kwargs):
        return cls(ownership_obj=ownership, meta_data_obj=meta_data,
                   time_valid_response=time_valid_response, offline=offline_mode,
                   scanner_id=scanner_id, backwards_propagation=backwards_propagation,
                   oois=cls.build_ooi_objects(raw_oois), **kwargs)

    @staticmethod
    @abstractmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        pass

    @property
    @abstractmethod
    def quota_amount(self) -> int:
        pass

    @staticmethod
    @abstractmethod
    def ooi_cls():
        pass

    @staticmethod
    @abstractmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        pass


    def _own_post_init(self):
        pass

    @property
    def get_ownership_obj(self) -> Ownership:
        return Ownership._from_son(self.ownership_as_son)

    @property
    def next_ooi_obj(self):
        return self.oois.pop(0) if len(self.oois) > 0 else None

    @property
    def ooi_count(self) -> int:
        return len(self.oois)

    @property
    def force(self) -> bool:
        return True if self.time_valid_response <= 0 else False

    @field_validator('oois')
    def check_oois(cls, v):
        ooi_cls = cls.ooi_cls()
        for ooi in v:
            if not isinstance(ooi, ooi_cls):
                raise ValueError(f'Only {ooi_cls} are allowed as OOI.')
        return v


class BaseScanner(metaclass=ScannerRegistryBase):
    def __init__(self, task: Task, logger, scanning_request: typing.Union[BaseScanningRequestForScannerObject] = None):
        self._task = task
        self.scanner_document: typing.Union[BaseScannerDocument] | None = None
        self.logger = logger
        self.scanning_request: typing.Union[BaseScanningRequestForScannerObject] | None = scanning_request
        self.redis_cache = RedisMongoCache()
        self.scanning_result = None
        self._redis_lock: redis_lock.Lock | None = None
        self.next_ooi_obj: typing.Type[OOI] | None = None
        self.api_usage_stats = None

        self.quota: QuotaMechanic | None = None
        self.user_quota: QuotaUserAPI | None = None
        self.retry_args = {}
        logging.getLogger("redis_lock.thread").disabled = True
        logging.getLogger("redis_lock").disabled = True

        self.quota_exception_minute = False
        self.quota_exception_day = False
        self._time_valid_response = 0
        self._init()

    def _init(self):
        pass

    @staticmethod
    def redis_key_for_api_blocking(*args):
        return None

    @staticmethod
    def scanner_has_quota() -> bool:
        return False

    @staticmethod
    @abstractmethod
    def get_scanner_mongo_document_class():
        pass

    @classmethod
    @abstractmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        pass

    @classmethod
    @abstractmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        """In some cases is it important to have a predefined config for ooi types. For example VirusTotal: The predefined config may be helpful to set up a request for a particular endpoint (IP, URL,...).
        The primary use case is the API and the connected workflows like the Report-Engine.
        Return: {<name of the config>: {config as kwargs for the scanner request}}"""
        return {scanner_name: {}}

    @classmethod
    @abstractmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        pass

    @classmethod
    def build_scanner_execution_information(cls, only_cls: bool = False,  **config) -> BaseScannerExecutionInformation:
        if only_cls:
            return cls.get_scanner_execution_information()
        return cls.get_scanner_execution_information()(**config)

    @staticmethod
    @abstractmethod
    def get_result_class() -> typing.Type[BaseScanningRequests]:
        pass

    @abstractmethod
    def _do_your_scanning_job(self):
        pass

    @staticmethod
    @abstractmethod
    def get_scanner_type() -> str:
        pass

    @classmethod
    @abstractmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        pass

    @classmethod
    def add_final_scanner_to_system(cls, config: InitScanner_config):
        new_scanner_db = cls.add_scanner_to_system_stuff(config.args)
        new_scanner_db.name = config.name
        new_scanner_db.scanner_type = config.scanner_type
        new_scanner_db.default_scanner = config.default
        new_scanner_db.ensure_indexes()
        new_scanner_db.validate(clean=True)
        as_son = new_scanner_db.to_mongo()
        if '_id' in as_son:
            del as_son['_id']
        if new_scanner_db.default_scanner:
            try:
                x = BaseScannerDocument.objects.get(__raw__={'$and': [{'_cls': new_scanner_db._cls},
                                                                  {'scanner_type': new_scanner_db.scanner_type},
                                                                  {'default_scanner': True},
                                                                  {'name': {'$ne': new_scanner_db.name}}]})
            except DoesNotExist:
                pass
            else:
                raise NotUniqueError(f'Only one default scanner is allowed. {new_scanner_db.to_mongo()}')
        return BaseScannerDocument.objects(__raw__={'_cls': new_scanner_db._cls, 'name': new_scanner_db.name}).modify(__raw__={'$set':as_son}, new=True, upsert=True)


    @property
    def kwargs_for_building_scanning_request(self) -> dict:
        return {}

    @property
    def bulk_scanner(self) -> bool:
        return False

    @property
    def additional_filter_fields(self) -> dict:
        return {}

    @property
    def _filter_dict(self) -> dict:
        if self.with_scanner_id:
            x = {'ooi': self.next_ooi_obj.ooi,
                 'scanner': self.scanning_request.scanner_id}
        else:
            x = {'ooi': self.next_ooi_obj.ooi}
        x.update(self.additional_filter_fields)
        return x

    @property
    def _redis_lock_name(self):
        return str(hashlib.md5(f'lock._{self._filter_dict}'.encode()).hexdigest())

    @property
    def get_last_valid_result_filter(self) -> dict:
        x = self._filter_dict
        if self.scanning_request.offline:
            return x
        else:
            #TODO: Why not ttl?!?!?!?!
            x.update({'_id': {'$gte': ObjectId.from_datetime(
                (datetime.datetime.utcnow() - datetime.timedelta(seconds=self.scanning_request.time_valid_response)))}})
            return x

    @property
    def _redis_cache_key(self):
        return str(hashlib.md5(f'{self._filter_dict}'.encode()).hexdigest())

    @property
    def meta_data_as_son(self) -> SON:
        return self.scanning_request.meta_data_as_son

    @property
    def offline_get_failed_ooi_s(self):
        return self.next_ooi_obj.ooi

    @property
    def with_scanner_id(self) -> bool:
        return False

    def max_retries_exceeded_handling(self):
        pass

    def _get_backwards_propagation_id(self, backwards: Backpropagation):
        if self.bulk_scanner:
            x = []
            for i in backwards.id_ooi_mapping.values():
                x.extend(i)
            return x
        else:
            return backwards.id_ooi_mapping.get(str(self.next_ooi_obj.ooi), [])

    def offline_mode(self):
        """ For bulk scanner -> overwrite it"""
        self._get_redis_or_mongo_db_cache()
        if self.scanning_result:
            self._update_tags()
        else:
            raise OfflineModeNoResult()

    def convert_ooi_to_db_type(self, ooi=None):
        return str(ooi if ooi else self.next_ooi_obj.ooi)

    def set_up(self, scanner_id: ObjectId):
        self.scanner_document = self.get_scanner_mongo_document_class().objects.get(id=scanner_id)

    def _set_up_quota(self):
        if self.__class__.scanner_has_quota() and not self.quota:
            self.quota = QuotaMechanic(cache_key=str(self.scanner_document.id))

    def scan(self, scanning_request, next_ooi: OOI):
        self.scanning_request = scanning_request
        self._set_up_quota()
        if self.scanning_request.time_valid_response and self.scanning_request.time_valid_response > 0:
            self._time_valid_response = self.scanning_request.time_valid_response
        self.next_ooi_obj = next_ooi
        self.scanning_result = None
        try:
            if self.scanning_request.offline:
                self.offline_mode()
            elif self.scanning_request.force or self.bulk_scanner:
                self._process_scanning_request()
            else:
                self._get_redis_or_mongo_db_cache()
                if self.scanning_result:
                    if self._check_cache_not_too_old():
                        self._update_tags()
                    else:
                        self._process_scanning_request()
                else:
                    self._process_scanning_request()
        except (RetryException, LongTermRetryException):
            raise
        except Exception:
            self.logger.error(traceback.format_exception(*sys.exc_info()))
            raise
        finally:
            if self._redis_lock:
                try:
                    self._redis_lock.release()
                except Exception:
                    pass
            try:
                self.finally_stuff()
            except Exception:
                pass
            if self.scanning_result and self.scanning_request.backwards_propagation:
                db = get_db('Katti')
                for backward_propagation in self.scanning_request.backwards_propagation:
                    db[backward_propagation.collection].update_many(
                        {'_id': {'$in': self._get_backwards_propagation_id(backward_propagation)}},
                        {'$push': {f'backpropagation.{backward_propagation.field_name}': self.scanning_result.id}})

    def finally_stuff(self):
        pass

    def _build_scanning_result(self):
        self.scanning_result = self.get_result_class().build_new_request(meta_data=self.meta_data_as_son,
                                                                       id=ObjectId(),
                                                                       ooi=self.convert_ooi_to_db_type(),
                                                                       scanner=self.scanner_document,
                                                                       ownership=self.scanning_request.get_ownership_obj,
                                                                       **self.kwargs_for_building_scanning_request)

    def _process_scanning_request(self):
        self._quota_exception = False
        self._api_error_exception = False
        try:
            self._build_scanning_result()
            self._check_quota()
            self._redis_lock = redis_lock.Lock(self.redis_cache.redis_connection, name=self._redis_lock_name,
                                               expire=self.scanner_document.max_wait_time_for_cache) if not self.bulk_scanner else None
            if self.bulk_scanner or self._redis_lock.acquire():
                self._do_your_scanning_job()
            elif not self._wait_for_valid_result():
                self._do_your_scanning_job()
        except (QMinute, MinuteBlockException) as e:
            self.logger.debug(f'Quota block: {e}')
            self.quota_exception_minute = True
            self.scanning_result.quota_exception = f'{e}'
        except (QDay, DayBlockException) as e:
            self.quota_exception_day = True
            self.logger.debug(f'Quota block: {e}')
            self.scanning_result.quota_exception = f'{e}'
        except APIErrorException as e:
            self.scanning_result.api_error = e.text
            self._api_error_exception = True
        finally:
            self._save_new_scanning_result()

    def _check_cache_not_too_old(self, ):
        if not self.scanning_result or not (datetime.datetime.utcnow() - self.scanning_result.katti_create).total_seconds() < self._time_valid_response:
            return False
        return True

    def _get_redis_or_mongo_db_cache(self):
        self.scanning_result = self.redis_cache.get_mongoengine_cache(mongoengine_cls=self.get_result_class(),
                                                                      cache_key=self._redis_cache_key,
                                                                      mongo_filter=self.get_last_valid_result_filter)

    def _save_scanning_result_to_redis(self):
        self.redis_cache.set_mongoengine_object(cache_key=self._redis_cache_key,
                                                mongoengine_object=self.scanning_result,
                                                ttl=self.scanner_document.time_valid_response)

    def _save_new_scanning_result(self):
        if self.scanning_result and not (self.quota_exception_minute or self.quota_exception_day or self._api_error_exception):
            self.scanning_result.save()
            if not self.bulk_scanner:
                self._save_scanning_result_to_redis()

        elif self.scanning_result and self.quota_exception_day:
            if self.scanning_request.quota_exception_day_retry:
                time_now = datetime.datetime.utcnow()
                x = (time_now + datetime.timedelta(days=1)).replace(hour=3, minute=30)
                wait_time = (x - time_now).total_seconds()
                self.retry_args.update({'countdown': wait_time})
                raise LongTermRetryException()
            self._error_save_result()
            #raise DayBlockException()

        elif self.scanning_result and self.quota_exception_minute:
            if self.scanning_request.quota_exception_minute_retry:
                self.retry_args.update({'countdown': randint(90, 300)})
                raise RetryException()
            self._error_save_result()
          #  raise MinuteBlockException()

        elif self.scanning_result and self._api_error_exception:
            self._error_save_result()
           # raise APIErrorException()

        elif not self.scanning_result:
            self.logger.error('No scanning result.')
            raise ExtremeFailure('No scanning result')

    def _error_save_result(self):
        x = self.scanning_result.to_mongo()
        x.update({'_cls': self.scanning_result._cls,
                  'scanning_request': pickle.dumps(self.scanning_request)})
        ErrorParking._get_collection().insert_one(x)

    def _wait_for_valid_result(self):
        start_wait_time = datetime.datetime.now()
        while (datetime.datetime.now() - start_wait_time).seconds < self.scanner_document.max_wait_time_for_cache:
            self._get_redis_or_mongo_db_cache()
            if self.scanning_result and self._check_cache_not_too_old():
                return True
            time.sleep(0.33)
        self.logger.debug('I have wait to long for the result.')
        return False

    def _update_tags(self):
        if self.meta_data_as_son:
            self.scanning_result.update_exiting_request_in_db(self.meta_data_as_son)

    def _check_quota(self):
        if not self.scanning_request.api_request:
            #Quota check -> API!
            if not self.user_quota:
                time_lord = self.redis_cache.get_mongoengine_cache(
                    cache_key=str(self.scanning_request.ownership_as_son['owner']),
                    mongoengine_cls=TimeLord,
                    mongo_filter={'id': self.scanning_request.ownership_as_son['owner']},
                    as_son=True)
                if not time_lord:
                    self.logger.error(f'{self.scanning_request.ownership_as_son["owner"]} is not a valid timelord id.')
                    raise ExtremeFailure(f'No valid time lord id {self.scanning_request.ownership_as_son["owner"]}')
                self.user_quota = QuotaUserAPI(time_lord_id=self.scanning_request.ownership_as_son['owner'])
                self.user_quota.set_endpoint(time_lord['api'].get('endpoints', []),
                                             endpoint_=self.__class__.get_scanner_type())
            self.user_quota.enough_quota(self.scanning_request.quota_amount)
        if not self.quota:
            return
        else:
            self.quota.check_day_block()
            self.quota.check_minute_block()
