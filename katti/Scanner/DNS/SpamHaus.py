import ipaddress
import subprocess
import sys
import traceback
import typing
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSBL import SpamHausDB, SpamHausRequest
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    ZenspamhausExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.KattiUtils.Exceptions.ScannerExceptions import NoIPv4
from katti.KattiUtils.HelperFunctions import is_valid_ipv4
from katti.Scanner.BaseScanner import OOI, BaseScanningRequestForScannerObject, BaseScanner
from katti.Scanner.DNS.Helpers import execute_dig_cmd, reverse_ip


@dataclass(config=PydanticConfig)
class IPForSpamhaus(OOI):
    raw_ooi: ipaddress.IPv4Address


@dataclass(config=PydanticConfig)
class IPsForSpamhaus(BaseScanningRequestForScannerObject):

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        x = []
        for ip in raw_oois:
            if isinstance(ip, ipaddress.IPv4Address) or is_valid_ipv4(ip):
                x.append(IPForSpamhaus(raw_ooi=ipaddress.IPv4Address(ip)))
        if len(x) == 0:
            raise NoIPv4()
        return x

    @staticmethod
    def ooi_cls():
        return IPForSpamhaus

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


class SpamHaus(BaseScanner):
    scanner_document: SpamHausDB
    scanning_result: SpamHausRequest
    scanning_request: IPsForSpamhaus

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import spamhaus
        return [IPsForSpamhaus, spamhaus]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        return super().pre_defined_config_for_ooi_type(scanner_name, ooi_type)

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return ZenspamhausExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'spamhaus'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return SpamHausDB(**config)

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return SpamHausRequest

    @staticmethod
    def get_scanner_mongo_document_class():
        return SpamHausDB

    def _do_your_scanning_job(self):
        try:
            data = execute_dig_cmd(
                request_str=f'{reverse_ip(self.next_ooi_obj.ooi)}.{self.scanner_document.name_server_name}',
                record_type='A',
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
                    case 'NXDOMAIN':
                        self.scanning_result.error_reason = 'No matching DB entry'
                    case 'NOERROR' if len(self._response_data.get('answer', [])) > 0:
                        self._parse_a_record(self._response_data['answer'])
                    case _:
                        self.scanning_result.error_reason = 'Unknown'
            except Exception:
                self.logger.exception(traceback.format_exception(*sys.exc_info()))
                self.scanning_result.error_reason = 'Unknown'

    def _parse_a_record(self, a_records: list):
        for record in a_records:
            if record.get('data'):
                mapping = self.scanner_document.record_mapping.get(record['data'].replace('.', ''))
                if mapping:
                    self.scanning_result.add_mapping(mapping)
                else:
                    self.scanning_result.add_unknown_mapping(record.get('data', ''))