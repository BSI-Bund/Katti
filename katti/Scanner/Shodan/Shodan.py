import datetime
import hashlib
import ipaddress
import json
import time
import typing
from random import randint
from typing import Type
from mongoengine.fields import dateutil
import shodan
from shodan import APIError
import katti.redis_lock as redis_lock
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.Shodan import ShodanScannerDB, ShodanScanRequest, traverse_result, \
    ShodanCrawlerResult, ShodanMeta, SubResults
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    ShodanExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.KattiUtils.HelperFunctions import split
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI
from pydantic import field_validator, Field
from bson import ObjectId

@dataclass(config=PydanticConfig)
class IPsForShodan(OOI):
    raw_ooi: list[typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = Field(default_factory=list, max_items=100, min_items=1)

    @property
    def ooi(self):
        return self.raw_ooi


@dataclass(config=PydanticConfig)
class ShodanScanningRequest(BaseScanningRequestForScannerObject):
    @field_validator('oois')
    def check_oois(cls, v):
        if len(v) > 1 or len(v) == 0:
            raise ValueError('Only one IPsForShodan are allowed, but min. 1.')
        if not isinstance(v[0], IPsForShodan):
            raise ValueError('Only IPsForShodan are allowed.')
        return v

    @staticmethod
    def ooi_cls():
        return IPsForShodan

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [IPsForShodan(raw_ooi=[ipaddress.ip_address(ip) for ip in raw_oois])]

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        match ooi_type:
            case 'ipv4' | 'ipv6' | 'ips':
                return True
            case _:
                return False

class ShodanScanner(BaseScanner):
    scanning_request: BaseScanningRequestForScannerObject
    scanner_document: ShodanScannerDB

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import shodan_api_call_task
        return [ShodanScanningRequest, shodan_api_call_task]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        return super().pre_defined_config_for_ooi_type(scanner_name, ooi_type)

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return ShodanExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'shodan'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return ShodanScannerDB(**config)

    @staticmethod
    def scanner_has_quota() -> bool:
        return True

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return ShodanScanRequest

    @property
    def bulk_scanner(self) -> bool:
        return True

    @staticmethod
    def get_scanner_mongo_document_class():
        return ShodanScannerDB

    def _init(self):
        self._retry_counter = 0

    def convert_ooi_to_db_type(self):
        self.left_overs = []
        cls = SubResults()._cls
        min_object_id = ObjectId.from_datetime(
            datetime.datetime.utcnow() - datetime.timedelta(seconds=self.scanning_request.time_valid_response))
        ooi_ips = []
        self._cache_results = []
        for ip in self.next_ooi_obj.ooi:
            cache_result = self.redis_cache.get_mongoengine_cache(mongoengine_cls=SubResults,
                                                                  cache_key=f'shodan_sub{ip}',
                                                                  mongo_filter={'_cls': cls, 'ip': str(ip)})
            if cache_result and cache_result.id >= min_object_id:
                self._cache_results.append(cache_result)
            else:
                self.left_overs.append(str(ip))
            ooi_ips.append(str(ip))
        return ooi_ips

    def finally_stuff(self):
        try:
            self._shodan_lock.release()
        except Exception as e:
            pass

    def _wait_fock_lock(self):
        start_wait = datetime.datetime.utcnow()
        self._shodan_lock = redis_lock.Lock(self.redis_cache.redis_connection, name='shodanAPI', expire=1)
        while (datetime.datetime.utcnow() - start_wait).total_seconds() <= 3:
            if not self._shodan_lock.acquire():
                self.logger.debug('Have to wait for Lock.')
                time.sleep(0.3)
            else:
                break

    def _do_your_scanning_job(self):
        self.scanning_result.results = self._cache_results
        self.ips_in_result = []
        # self._check_cache()
        help = list(split(list_a=self.left_overs, chunk_size=100))
        while len(help) > 0:
            self._wait_fock_lock()
            ip_chunk = help.pop(0)
            try:
                res = shodan.Shodan(self.scanner_document.api_key).host(ip_chunk)
                self.finally_stuff()
            except APIError as e:
                if 'for that IP' in str(e):
                    self._build_api_error_sub_result(error='No Information available for that IP.', ips=ip_chunk)
                else:
                    self.finally_stuff()
                    self._retry_counter += 1
                    self.logger.error(f'API ERROR {e}, counter: {self._retry_counter}')
                    if self._retry_counter > 3:
                        self.scanning_result.api_error = str(e)
                    else:
                        time.sleep(randint(3,20))
                        self._do_your_scanning_job()
            else:
                if isinstance(res, dict):
                    self._build_result(res)
                else:
                    for single_result in res:
                        self._build_result(single_result)
                    x = []
                    for ip in ip_chunk:
                        if ip in self.ips_in_result:
                            continue
                        else:
                            x.append(ip)
                    self._build_api_error_sub_result(error='No Information available for that IP.', ips=x)

    def _build_api_error_sub_result(self, error, ips: list):
        x = [SubResults(error=error, ip=ip, ttl=datetime.datetime.utcnow()) for ip in ips]
        if len(x) > 0:
            SubResults.objects.insert(x)
            self.scanning_result.results.extend(x)

    def _build_result(self, single_result):
        crawler_results = single_result.pop('data')
        new_sub_result = SubResults(katti_create=datetime.datetime.utcnow())
        self.ips_in_result.append(single_result['ip_str'])
        try:
            new_sub_result.shodan_last_update = dateutil.parser.parse(single_result['last_update'])
        except (TypeError, AttributeError) as e:
            pass
        new_sub_result.crawler_results = self._build_crawler_results(crawler_results)
        new_sub_result.shodan_meta = self._build_shodan_meta(single_result)
        new_sub_result.ip = single_result['ip_str']
        new_sub_result.save()
        self.scanning_result.results.append(new_sub_result)

    def _build_shodan_meta(self, shodan_meta):
        hash_str = hashlib.md5(json.dumps(shodan_meta).encode()).hexdigest()
        set_on_insert_dict = traverse_result(shodan_meta)
        return ShodanMeta.get_result_from_db(filter={'hash_str': hash_str},
                                             scanner_obj=self,
                                             ooi=None,
                                             set_on_insert_dict=set_on_insert_dict,
                                             only_id=True)

    def _build_crawler_results(self, crawler_results):
        final_crawler_results = []
        for crawler_result in sorted(crawler_results, key=lambda x: x['timestamp']):
            hash_str = hashlib.md5(json.dumps(crawler_result).encode()).hexdigest()
            set_on_insert_dict = traverse_result(crawler_result)
            final_crawler_results.append(
                ShodanCrawlerResult.get_result_from_db(filter={'hash_str': hash_str},
                                                       scanner_obj=self,
                                                       ooi=None,
                                                       set_on_insert_dict=set_on_insert_dict,
                                                       only_id=True))
        return final_crawler_results

    def handle_quota_block(self, exception: Exception):
        pass

    def offline_mode(self):
        self._build_scanning_result()
        self.scanning_result.results = []
        for ip in self.next_ooi_obj.ooi:
            x = SubResults.objects(ip=str(ip)).order_by('-id')[:1].only('id')
            self.scanning_result.results.append(x)
