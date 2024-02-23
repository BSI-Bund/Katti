import ipaddress
import subprocess
import sys
import traceback
import typing
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSBL import PTRConfig
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSServerConfig import DNSRequest, Evaluation
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    PTRRecordExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.KattiUtils.Exceptions.ScannerExceptions import NoIPv4
from katti.KattiUtils.HelperFunctions import is_valid_ipv4, is_ip_addr_valid
from katti.Scanner.BaseScanner import OOI, BaseScanningRequestForScannerObject, BaseScanner
from katti.Scanner.DNS.DNSResolver import DomainsForDNSResolverRequest
from katti.Scanner.DNS.Helpers import execute_dig_cmd_with_reverse


@dataclass(config=PydanticConfig)
class IPForPTR(OOI):
    raw_ooi: typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass(config=PydanticConfig)
class IPsForPTR(BaseScanningRequestForScannerObject):

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        x = []
        for ip in raw_oois:
            if isinstance(ip, ipaddress.IPv4Address) or is_valid_ipv4(ip):
                x.append(IPForPTR(raw_ooi=ipaddress.IPv4Address(ip)))
            elif isinstance(ip, ipaddress.IPv6Address) or is_ip_addr_valid(ip):
                x.append(IPForPTR(raw_ooi=ipaddress.IPv6Address(ip)))
        if len(x) == 0:
            raise NoIPv4()
        return x

    @staticmethod
    def ooi_cls():
        return IPForPTR

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


class PTRScanner(BaseScanner):
    scanner_document: PTRConfig
    scanning_request: IPsForPTR

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import ptr_scan
        return [IPsForPTR, ptr_scan]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        return super().pre_defined_config_for_ooi_type(scanner_name, ooi_type)

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return PTRRecordExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'ptr_scanner'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return PTRConfig(**config)

    @property
    def with_scanner_id(self) -> bool:
        return True

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return DNSRequest

    @staticmethod
    def get_scanner_mongo_document_class():
        return PTRConfig

    def _do_your_scanning_job(self):
        try:
            data = execute_dig_cmd_with_reverse(
                request_str=f'{self.next_ooi_obj.ooi}',
                record_type='PTR',
                name_server=self.scanner_document.dns_resolver_ip)
        except subprocess.TimeoutExpired:
            self.logger.exception(f'Timeout: {self.next_ooi_obj.ooi}')
            self.scanning_result.error_reason = 'TIMEOUT'
        except Exception:
            self.logger.exception(f'DIGFAIL ({self.next_ooi_obj.ooi}): {traceback.format_exception(*sys.exc_info())}')
            self.scanning_result.error_reason = 'DIGFAIL'
        else:
            try:
                response_data = data[0]
                if response_data.get('status', '') == 'SERVFAIL':
                    query = DNSRequest.DNSQuery(status='SERVFAIL')
                else:
                    query = DNSRequest.DNSQuery().build_response(response_data,
                                                                 scanner=self,
                                                                 evaluation_settings=[Evaluation(type='ptr_stuff',
                                                                                                 settings=[{'hints': self.scanner_document.static_hints, 'hint_type': 'static'},
                                                                                                           {'hints': self.scanner_document.dynamic_hints, 'hint_type': 'dynamic'}])],
                                                                 ooi=self.next_ooi_obj.ooi,
                                                                 katti_meta_data=self.meta_data_as_son)
            except Exception:
                self.logger.exception(f'{traceback.format_exception(*sys.exc_info())}')
                query = DNSRequest.DNSQuery(status='NOVALIDRESPONSE')
            finally:
                self.scanning_result.queries.append(query)
        finally:
            self.scanning_result.ptr = True
