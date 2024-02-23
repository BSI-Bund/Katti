import hashlib
import ipaddress
import json
import typing
from random import randint
import requests
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.DataBaseStuff.MongoengineDocuments.Scanner.MaxMindOffline import MaxMindOfflineDB, MaxMindResultASN, \
    MaxMindResultCountryCity, MaxMindOfflineRequest
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    MaxMindExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI, RetryException


@dataclass(config=PydanticConfig)
class MaxMindOOI(OOI):
    raw_ooi: typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass(config=PydanticConfig)
class IPsForMaxMind(BaseScanningRequestForScannerObject):
    # db_type: typing.Literal['asn', 'city', 'all'] = 'all' #Country is subset of city

    @staticmethod
    def ooi_cls():
        return MaxMindOOI

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [MaxMindOOI(raw_ooi=ipaddress.ip_address(ip)) for ip in raw_oois]

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


class MaxMindOffline(BaseScanner):
    scanning_request: IPsForMaxMind
    scanner_document: MaxMindOfflineDB
    scanning_result: MaxMindOfflineRequest

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import maxmind
        return [IPsForMaxMind, maxmind]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        return super().pre_defined_config_for_ooi_type(scanner_name, ooi_type)

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return MaxMindExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'maxmind_offline'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return MaxMindOfflineDB(**config)

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return MaxMindOfflineRequest

    @staticmethod
    def get_scanner_mongo_document_class():
        return MaxMindOfflineDB

    @property
    def with_scanner_id(self) -> bool:
        return False

    def _do_your_scanning_job(self):
        #  match self.scanning_request.db_type:
        #      case 'all':
        #          self._do_request(endpoint='asn')
        #          self._do_request(endpoint='city')
        #      case 'city' | 'asn' | 'country':
        #          self._do_request(endpoint=self.scanning_request.db_type)
        self._do_request(endpoint='asn')
        self._do_request(endpoint='city')
        self.scanning_result.db_type = 'all'  # self.scanning_request.db_type

    def _do_request(self, endpoint):
        try:
            response = requests.post(
                f'http://{self.scanner_document.docker_ip}:{self.scanner_document.docker_port}/{endpoint}',
                data=json.dumps({'ips': [self.next_ooi_obj.ooi]}), timeout=10)
        except requests.exceptions.ConnectionError:
            self.logger.error(f'ConnectionError, server down?')
            self.retry_args.update({'countdown': randint(30*60, 60*60)})
            raise RetryException()
        match response.status_code:
            case 200:
                match endpoint:
                    case 'asn':
                        x = json.loads(response.content.decode())
                        for result in x:
                            if 'error' in result[1]:
                                self.scanning_result.add_error({'ip': result[0], 'error': result[1].get('error')})
                                continue

                            self.scanning_result.asn = MaxMindResultASN.get_result_from_db(scanner_obj=self,
                                                                                           filter=result[1],
                                                                                           ooi=result[0], only_id=True)
                    case 'city' | 'country':
                        x = json.loads(response.content.decode())
                        for result in x:
                            if 'error' in result[1]:
                                self.scanning_result.add_error({'ip': result[0], 'error': result[1].get('error')})
                                continue
                            self.scanning_result.city_country = MaxMindResultCountryCity.get_result_from_db(
                                filter={'ooi': result[0],
                                        'hash_str': hashlib.md5(json.dumps(result[1]).encode()).hexdigest()},
                                update={'$setOnInsert': result[1]},
                                scanner_obj=self,
                                with_scanner_id=self.with_scanner_id,
                                ooi=None,
                                only_id=True)
            case _:
                self.logger.error(f'Bad status code {response.status_code}')
                raise Exception('Bad status code {response.status_code}')

    def offline_mode(self):
        self._do_your_scanning_job()
