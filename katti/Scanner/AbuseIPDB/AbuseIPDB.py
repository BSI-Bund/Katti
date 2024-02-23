import hashlib
import ipaddress
import json
import typing
import requests
from bson import ObjectId

from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    AbuseIPDBExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.Scanner.QuotaMechanic import DayBlockException
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Common.Link import IP
from katti.DataBaseStuff.MongoengineDocuments.Scanner.AbuseIPDB import AbsueIPDBRequest, AbuseIPDBDB, AbuseIPDBReport
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI
from mongoengine.fields import dateutil


@dataclass(config=PydanticConfig)
class AbuseIPOOI(OOI):
    raw_ooi = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass(config=PydanticConfig)
class AbuseIPDBIPs(BaseScanningRequestForScannerObject):
    max_age_days: int = 30

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [AbuseIPOOI(raw_ooi=ipaddress.ip_address(ip)) for ip in raw_oois]

    @staticmethod
    def ooi_cls():
        return AbuseIPOOI

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        match ooi_type:
            case 'ips' | 'ipv4' | 'ipv6':
                return True
            case _:
                return False


class AbuseIPDBScanner(BaseScanner):
    scanner_document: AbuseIPDBDB
    scanning_request: AbuseIPDBIPs
    scanning_result: AbsueIPDBRequest

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import abuse_ip_db
        return [AbuseIPDBIPs, abuse_ip_db]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        return {scanner_name: {'max_age_days': 180}}

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return AbuseIPDBExecutionInformation

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return AbuseIPDBDB(**config)

    @staticmethod
    def get_scanner_type() -> str:
        return 'abuse_ip_db'

    @staticmethod
    def get_result_class() -> typing.Type[BaseScanningRequests]:
        return AbsueIPDBRequest

    @staticmethod
    def get_scanner_mongo_document_class():
        return AbuseIPDBDB

    @staticmethod
    def scanner_has_quota() -> bool:
        return True

    def _do_your_scanning_job(self):
        response = requests.get(f'{self.scanner_document.url}',
                                params={'ipAddress': str(self.next_ooi_obj.ooi),
                                        'verbose': True,
                                        'maxAgeInDays': self.scanning_request.max_age_days},
                                headers={
                                    'Key': self.scanner_document.api_key,
                                    'Accept': 'application/json'}
                                )
        match response.status_code:
            case 200:
                self._produce_response(json.loads(response.content.decode())['data'])
                self._update_remaining_quota(response.headers)
            case 429:
                self.quota.set_remaining_quota(0)
                raise DayBlockException()
            case _:
                self.logger.error(f'Bad status code {response.status_code} {self.next_ooi_obj.ooi}')
                self.scanning_result.errors = json.loads(response.content)

    def _update_remaining_quota(self, response_headers):
        if response_headers.get('X-RateLimit-Remaining'):
            self.quota.set_remaining_quota(response_headers.get('X-RateLimit-Remaining'))


    def _produce_response(self, raw_json):
        if raw_json['lastReportedAt']:
            self.scanning_result.lastReportedAt = dateutil.parser.parse(raw_json['lastReportedAt'])
        self.scanning_result.ip_addr = IP.build_from_ip_str(ip_str=raw_json['ipAddress'])
        self.scanning_result.abuseConfidenceScore = raw_json.get('abuseConfidenceScore')
        self.scanning_result.countryCode = raw_json.get('countryCode')
        self.scanning_result.countryName = raw_json.get('countryName')
        self.scanning_result.domain = raw_json.get('domain')
        self.scanning_result.hostnames = raw_json.get('hostnames')
        self.scanning_result.isPublic = raw_json.get('isPublic')
        self.scanning_result.isWhitelisted = raw_json.get('isWhitelisted')
        self.scanning_result.isp = raw_json.get('isp')
        self.scanning_result.numDistinctUsers = raw_json.get('numDistinctUsers')

        for report in raw_json['reports']:
            hash_str = hashlib.md5(json.dumps(report).encode()).hexdigest()
            report['reportedAt'] = dateutil.parser.parse(report['reportedAt'])
            self.scanning_result.reports.append(AbuseIPDBReport.get_result_from_db(filter={'hash_str': hash_str},
                                                                                   update={'$setOnInsert': report},
                                                                                   ooi=self.next_ooi_obj.ooi,
                                                                                   scanner_obj=self,
                                                                                   only_id=True))
