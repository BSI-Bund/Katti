import datetime
import json
import sys
import traceback
import typing
from typing import Type, Literal
import requests

from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    FarsightExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.Scanner.DNS.rdata_parser_functions import RDataParser
from pydantic import Field
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI
from katti.DataBaseStuff.MongoengineDocuments.Scanner.FarsightDocument import FarsightDocument, FarsightQuerryResult, FarsightRequest
from katti.Scanner.QuotaMechanic import DayBlockException

FARSIGHT_FIRST_PART_OF_URL = 'https://api.dnsdb.info/dnsdb/v2/lookup/'

@dataclass(config=PydanticConfig)
class FarsightOOI(OOI):
    raw_query: bool = False
    _ooi = None

    @property
    def ooi(self):
        if self._ooi:
            return self._ooi
        if not self.raw_query:
            self._ooi = self.raw_ooi
        if self.raw_query:
            self._ooi = self.raw_ooi.split(FARSIGHT_FIRST_PART_OF_URL)[1].split('/')[2]
        return self._ooi


@dataclass(config=PydanticConfig)
class FarsightQuerries(BaseScanningRequestForScannerObject):
    raw_query: bool = False
    record_type: str = 'ANY'
    rdata_or_rrset: Literal['rdata_name', 'rdata_ip', 'rrset'] = 'rrset'
    time_last_after: int | None = None
    time_first_before: int | None = None
    bailiwick: str | None = None
    limit: int = Field(default=5000, gt=0, lt=30000)

    @staticmethod
    def ooi_cls():
        return FarsightOOI

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [FarsightOOI(raw_ooi=x) for x in raw_oois]

    def get_url_for_ooi(self, next_ooi: FarsightOOI):
        if next_ooi.raw_query:
            return next_ooi.raw_ooi
        else:
            match self.rdata_or_rrset:
                case 'rrset':
                    second_part_str = f'rrset/name/{next_ooi.ooi}/{self.record_type}{("/"+self.bailiwick) if self.bailiwick else ""}?limit={self.limit}'
                case 'rdata_name':
                    second_part_str = f'rdata/name/{next_ooi.ooi}'
                case 'rdata_ip':
                    second_part_str = f'rdata/ip/{next_ooi.ooi}'
                case _:
                    raise Exception()
            second_part_str += f'&time_last_after={self.time_last_after}' if self.time_last_after else ""
            second_part_str += f'&time_first_before={self.time_first_before}' if self.time_first_before else ""
            return f'{FARSIGHT_FIRST_PART_OF_URL}{second_part_str}'

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        match ooi_type:
            case 'ipv4' | 'ipv6' | 'ips' | 'domains' | 'other':
                return True
            case _:
                return False

class Farsight(BaseScanner):
    scanning_request: FarsightQuerries
    scanner_document: FarsightDocument

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import farsight_scanning_task
        return [FarsightQuerries, farsight_scanning_task]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        match ooi_type:
            case 'ipv4' | 'ipv6':
                return {f'{scanner_name}_rdata_ip': {'rdata_or_rrset': 'rdata_ip'}}
            case 'domain':
                return {f'{scanner_name}_rdata_name': {'rdata_or_rrset': 'rdata_name'},
                        f'{scanner_name}_rrset': {'rdata_or_rrset': 'rrset'}}

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return FarsightExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'farsight'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return FarsightDocument(**config)

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return FarsightRequest

    @staticmethod
    def get_scanner_mongo_document_class():
        return FarsightDocument

    @staticmethod
    def scanner_has_quota() -> bool:
        return True

    @property
    def additional_filter_fields(self) -> dict:
        return {'url': self.scanning_request.get_url_for_ooi(self.next_ooi_obj)}

    def _do_your_scanning_job(self):
        url = self.scanning_request.get_url_for_ooi(self.next_ooi_obj)
        self.scanning_result.url = url
        try:
            farsight_response = requests.get(url, headers={'X-API-KEY': self.scanner_document.api_key})
        except Exception:
            self.logger.exception(f'Farsight fail: {traceback.format_exception(*sys.exc_info())}')
            raise
        else:
            match farsight_response.status_code:
                case 200:
                    for line in farsight_response.content.decode('utf-8').splitlines():
                        json_line = json.loads(line)
                        if 'cond' in json_line:
                            continue
                        result_json = json_line['obj']
                        self.scanning_result.result_counter += 1
                        self.scanning_result.farsight_querry_results.append(self._save_querry_result(result_json))
                case 429:
                    self.quota.set_remaining_quota(0)
                    raise DayBlockException()
                case _:
                    raise Exception(f'Unknown bad status code {farsight_response.status_code}')

    def _save_querry_result(self, result_json):
        rdata_parser = RDataParser()
        if len(result_json['rdata']) == 1:
            record_value = rdata_parser.do_it(record_type=result_json['rrtype'], rdata=result_json['rdata'][0])
        else:
            record_value = [rdata_parser.do_it(rdata, result_json['rrtype']) for rdata in result_json['rdata']]
        if 'zone_time_first' in result_json:
            result_json.update({'time_first': result_json.pop('zone_time_first'),
                                'time_last': result_json.pop('zone_time_last'),
                                'time_zone': True})

        return FarsightQuerryResult.get_result_from_db(filter={'ooi': result_json['rrname'],
                                                               'type': result_json['rrtype'],
                                                               'time_first': datetime.datetime.fromtimestamp(result_json['time_first']),

                                                               'bailiwick': result_json.get('bailiwick'),
                                                                'record': record_value},
                                                       ooi=None,
                                                       scanner_obj=self,
                                                       with_scanner_id=False,
                                                       update={'$max': {'time_last': datetime.datetime.fromtimestamp(result_json['time_last']), 'count': result_json['count']}},
                                                       only_id=True)


