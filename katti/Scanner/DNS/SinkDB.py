import ipaddress
import subprocess
import sys
import traceback
import typing
from mongoengine.fields import dateutil
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSBL import SinkDBRequest, SinkDBResult, SinkDB_DB
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    SinkDBExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.KattiUtils.Exceptions.ScannerExceptions import NoIPv4
from katti.KattiUtils.HelperFunctions import is_valid_ipv4
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI
from katti.Scanner.DNS.Helpers import execute_dig_cmd, reverse_ip


@dataclass(config=PydanticConfig)
class IPForSinkDB(OOI):
    raw_ooi: ipaddress.IPv4Address


@dataclass(config=PydanticConfig)
class IPsForSinkDB(BaseScanningRequestForScannerObject):

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        x = []
        for ip in raw_oois:
            if isinstance(ip, ipaddress.IPv4Address) or is_valid_ipv4(ip):
                x.append(IPForSinkDB(raw_ooi=ipaddress.IPv4Address(ip)))
        if len(x) == 0:
            raise NoIPv4()
        return x

    @staticmethod
    def ooi_cls():
        return IPForSinkDB

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        match ooi_type:
            case 'ipv4':
                return True
            case _:
                return False


class SinkDB(BaseScanner):
    scanner_document: SinkDB_DB
    scanning_request: IPsForSinkDB
    scanning_result: SinkDBRequest

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import sinkdb
        return [IPsForSinkDB, sinkdb]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        return super().pre_defined_config_for_ooi_type(scanner_name, ooi_type)

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return SinkDBExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'sink_db'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return SinkDB_DB(**config)

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return SinkDBRequest

    @staticmethod
    def get_scanner_mongo_document_class():
        return SinkDB_DB

    def _do_your_scanning_job(self):
        # raise RetryException()
        try:
            data = execute_dig_cmd(
                request_str=f'{reverse_ip(self.next_ooi_obj.ooi)}.{self.scanner_document.api_key}.{self.scanner_document.name_server_name}',
                record_type='TXT',
                name_server=self.scanner_document.dns_resolver_ip)
        except subprocess.TimeoutExpired:
            self.logger.exception(f'Timeout: {self.next_ooi_obj.ooi}')
            self.scanning_result.error_reason = 'TIMEOUT'
        except Exception:
            self.logger.exception(f'DIGFAIL ({self.next_ooi_obj.ooi}): {traceback.format_exception(*sys.exc_info())}')
            self.scanning_result.error_reason = 'DIGFAIL'
        else:
            try:
                self._response_data = data[0]
                match self._response_data.get('status', ''):
                    case 'SERVFAIL':
                        self.scanning_result.error_reason = 'No valid API key.'
                    case 'NXDOMAIN':
                        self.scanning_result.error_reason = 'No matching DB entry'
                    case 'NOERROR' if len(self._response_data.get('answer', [])) > 0:
                        self._parse_text_record(self._response_data['answer'][0]['data'])
                    case _:
                        self.scanning_result.error_reason = f'Unknown: {self._response_data.get("status", "N/A")}'
            except Exception:
                self.logger.exception(traceback.format_exception(*sys.exc_info()))
                self.scanning_result.error_reason = 'Unknown'

    def _parse_text_record(self, txt):
        txt_split = txt.split(',')
        self.scanning_result.results = SinkDBResult(type=txt_split[1], classification=txt_split[2],
                                                    operator=txt_split[3],
                                                    date_added=dateutil.parser.parse(txt_split[4]),
                                                    expose_org=int(txt_split[5]))
