import datetime
import hashlib
import json
import sys
import traceback
import typing
from typing import Type
from aiohttp import client_exceptions
import vt
from pydantic import Field
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.VirusTotalConfig import VirusTotalConfig
from katti.DataBaseStuff.MongoengineDocuments.Scanner.VirusTotalScanningRequestResult import VirusTotalScanningRequest, \
    VirusTotalUniversalURLResult, VirusTotalUniversalIPResult, VirusTotalUniversalFileResult, \
    VirusTotalUniversalDomainResult
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    VirusTotalExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.KattiUtils.Exceptions.ScannerExceptions import LongTermRetryException
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI, RetryException
from katti.Scanner.QuotaMechanic import DayBlockException, MinuteBlockException


@dataclass(config=PydanticConfig)
class IOCsForVT(OOI):
    pass


@dataclass(config=PydanticConfig)
class IOCsForVTRequest(BaseScanningRequestForScannerObject):
    endpoint: str = Field(default='urls')
    own_api_key: str | None = None

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [IOCsForVT(raw_ooi=vt_ooi) for vt_ooi in raw_oois]

    @staticmethod
    def ooi_cls():
        return IOCsForVT

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        return True


class VirusTotal(BaseScanner):
    VT_URL_ENDPOINT: str = 'urls'
    VT_IP_ENDPOINT = 'ip_addresses'
    VT_HASH_ENDPOINT = 'static'
    VT_DOMAIN_ENDPOINT = 'domains'

    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import vt_scanning_task
        return [IOCsForVT, vt_scanning_task]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        endpoint = None
        match ooi_type:
            case 'url':
                endpoint = cls.VT_URL_ENDPOINT
            case 'ipv4' | 'ipv6':
                endpoint = cls.VT_IP_ENDPOINT
            case 'domain':
                endpoint = cls.VT_DOMAIN_ENDPOINT
            case 'hash':
                endpoint = cls.VT_HASH_ENDPOINT
        if endpoint:
            return {f'{scanner_name}_{ooi_type}': {'endpoint': endpoint}}

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return VirusTotalExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'virus_total'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return VirusTotalConfig(**config)

    @staticmethod
    def get_endpoints() -> list[str]:
        return [VirusTotal.VT_DOMAIN_ENDPOINT, VirusTotal.VT_URL_ENDPOINT, VirusTotal.VT_HASH_ENDPOINT, VirusTotal.VT_IP_ENDPOINT]

    scanner_document: VirusTotalConfig
    scanning_request: IOCsForVTRequest

    @staticmethod
    def scanner_has_quota() -> bool:
        return True

    @property
    def kwargs_for_building_scanning_request(self) -> dict:
        return {'api_endpoint': self.scanning_request.endpoint,
                'own_api_key': self.scanning_request.own_api_key}

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return VirusTotalScanningRequest

    @staticmethod
    def get_scanner_mongo_document_class():
        return VirusTotalConfig

    @property
    def additional_filter_fields(self) -> dict:
        return {'api_endpoint': self.scanning_request.endpoint}

    def _do_your_scanning_job(self):
        self._vt_client = vt.Client(self.scanner_document.api_key)
        self._get_vt_answer()

    def _get_vt_answer(self):
        match self.scanning_request.endpoint:
            case 'urls':
                ioc = vt.url_id(self.next_ooi_obj.ooi)
            case _:
                ioc = self.next_ooi_obj.ooi
        try:
            response = self._vt_client.get_json("/{}/{}".format(self.scanning_request.endpoint, ioc))['data'][
                'attributes']
            self._hash_answer_string = hashlib.md5(json.dumps(response).encode()).hexdigest()
            self._escape(response)
            self._produce_dates(response)
            self._produce_analysis_results(response)
            self._produce_categories(response)
            self._build_result(response)
        except vt.APIError as e:
            if e.code == 'NotFoundError':
                self._hash_answer_string = hashlib.md5(json.dumps({'response': 'NotFoundError', 'ooi': self.next_ooi_obj.ooi}).encode()).hexdigest()
                self._build_result(response={'response': 'NotFoundError'})
            elif e.code == 'QuotaExceededError':
                self._ups_quota_failure()
            else:
                self.logger.debug(f'VT Error {e}')
        except (ConnectionResetError, client_exceptions.ClientConnectorError):
            self.logger.error(traceback.format_exception(*sys.exc_info()))
            raise RetryException()

    def _build_result(self, response):
        response.update({'ooi': self.next_ooi_obj.ooi})
        self.scanning_result.api_endpoint = self.scanning_request.endpoint
        match self.scanning_request.endpoint:
            case VirusTotal.VT_URL_ENDPOINT:
                response.update({'vt_id': vt.url_id(self.next_ooi_obj.ooi)})
                self.scanning_result.result = VirusTotalUniversalURLResult.get_result_from_db(
                    filter={'hash_string': self._hash_answer_string},
                    ooi=self.next_ooi_obj.ooi,
                    scanner_obj=self,
                    set_on_insert_dict=response, only_id=True)
            case VirusTotal.VT_IP_ENDPOINT:
                self.scanning_result.result = VirusTotalUniversalIPResult.get_result_from_db(
                    filter={'hash_string': self._hash_answer_string},
                    ooi=self.next_ooi_obj.ooi,
                    scanner_obj=self,
                    set_on_insert_dict=response, only_id=True)
            case VirusTotal.VT_HASH_ENDPOINT:
                self.scanning_result.result = VirusTotalUniversalFileResult.get_result_from_db(
                    filter={'hash_string': self._hash_answer_string},
                    ooi=self.next_ooi_obj.ooi,
                    scanner_obj=self,
                    set_on_insert_dict=response, only_id=True)
            case VirusTotal.VT_DOMAIN_ENDPOINT:
                self.scanning_result.result = VirusTotalUniversalDomainResult.get_result_from_db(
                    filter={'hash_string': self._hash_answer_string},
                    ooi=self.next_ooi_obj.ooi,
                    scanner_obj=self,
                    set_on_insert_dict=response, only_id=True)

    def _escape(self, dic):
        for key in dic:
            if '.' in key:
                dic[key.replace('.', '(punkt)')] = dic[key]
                del dic[key]
                return self._escape(dic)
            if '$' in key:
                dic[key.replace('$', '(dollar)')] = dic[key]
                del dic[key]
                return self._escape(dic)
            for vl in dic.values():
                if isinstance(vl, dict):
                    self._escape(vl)

    def _produce_dates(self, response):
        date_fields = ['first_submission_date', 'last_analysis_date', 'last_modification_date', 'last_submission_date',
                       'whois_date', 'last_dns_records_date', 'last_https_certificate_date']
        for date_field in date_fields:
            try:
                if date_field in response:
                    response[date_field] = datetime.datetime.fromtimestamp(response[date_field])
                self._escape(response)
            except Exception:
                pass

    def _produce_analysis_results(self, response):
        if 'last_analysis_results' in response:
            results = [{'partner': partner,
                        'result': result} for partner, result in response.get('last_analysis_results', {}).items()]
            response['last_analysis_results'] = results

    def _produce_categories(self, response):
        if 'categories' in response:
            results = [{'partner': partner,
                        'result': result} for partner, result in response.get('categories', {}).items()]
            response['categories'] = results

    def _ups_quota_failure(self):
        try:
            vt_quota = self._vt_client.get_json("/{}/{}".format('users', self.scanner_document.api_key))['data']['attributes']['quotas']['api_requests_daily']
        except Exception:
            self.quota.set_remaining_quota(0)
            self.logger.error(traceback.format_exception(*sys.exc_info()))
            raise DayBlockException()
        else:
            if vt_quota['allowed'] >= vt_quota['used']:
                self.quota.set_remaining_quota(0)
                raise DayBlockException()
            else:
                raise MinuteBlockException()
