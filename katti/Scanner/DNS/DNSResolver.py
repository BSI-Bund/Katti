import copy
import subprocess
import sys
import traceback
import typing
from bson import ObjectId

from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    DNSExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.Scanner.Helpers import preexec_function
from katti.KattiUtils.HelperFunctions import is_valid_domain
from pydantic import Field, field_validator
from pydantic.dataclasses import dataclass
import katti.jc as jc
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSServerConfig import DNSRequest, DNSConfig


@dataclass(config=PydanticConfig)
class DomainForDNS(OOI):
    any_failed_origin_id: ObjectId | None = None
    any_failed_dig_type: str | None = None

    @field_validator('raw_ooi')
    def validate_ooi(cls, v):
        if not is_valid_domain(v):
            raise ValueError('Only domains are allowed.')
        else:
            return v


@dataclass(config=PydanticConfig)
class DomainsForDNSResolverRequest(BaseScanningRequestForScannerObject):
    dig_flags: list = Field(default_factory=list)
    dig_type: str = 'ANY'
    with_dnssec: bool = False
    ignore_fail: bool = True

    @staticmethod
    def ooi_cls():
        return DomainForDNS

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [DomainForDNS(raw_ooi=domain) for domain in raw_oois]

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        match ooi_type:
            case 'domain':
                return True
            case _:
                return False


class DNSResolver(BaseScanner):
    scanner_document: DNSConfig
    scanning_request: DomainsForDNSResolverRequest

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import dns_scanning_task
        return [DomainsForDNSResolverRequest, dns_scanning_task]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        match scanner_name:
            case 'google':
                return {scanner_name: {'dig_type': 'ANY'}}
            case _:
                return {scanner_name: {'dig_type': 'A'}}

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return DNSExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'dns'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return DNSConfig(**config)

    @property
    def with_scanner_id(self) -> bool:
        return True

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return DNSRequest

    @property
    def kwargs_for_building_scanning_request(self) -> dict:
        if self.next_ooi_obj.any_failed_origin_id:
            return {'dig_type': self._dig_type, 'any_failed_origin_request': self.next_ooi_obj.any_failed_origin_id}
        else:
            return {'dig_type': self._dig_type}

    @staticmethod
    def get_scanner_mongo_document_class():
        return DNSConfig

    @property
    def additional_filter_fields(self) -> dict:
        return {'dig_type': self._dig_type}

    @property
    def _dig_type(self):
        return self.next_ooi_obj.any_failed_dig_type if self.next_ooi_obj.any_failed_dig_type else self.scanning_request.dig_type

    def _do_your_scanning_job(self):
        self._backup_records = self.scanner_document.any_backup_records
        #raise RetryException()
        name_servers = copy.deepcopy(self.scanner_document.name_server_ips)
        next_name_server = name_servers.pop(0)
        servfail = 0
        if self.scanning_request.with_dnssec:
            cmd_list = ['dig', '+dnssec', f'@{next_name_server}', f'{self.next_ooi_obj.ooi}', self._dig_type]
        else:
            cmd_list = ['dig', f'@{next_name_server}', f'{self.next_ooi_obj.ooi}', self._dig_type]
        while True:
            try:
                cmd_output = subprocess.check_output(cmd_list, text=True, timeout=15, preexec_fn=preexec_function)
                data = jc.parse('dig', cmd_output)
            except subprocess.TimeoutExpired:
                self.logger.info(f'Timeout: {self.next_ooi_obj.ooi}')
                query = DNSRequest.DNSQuery(status='TIMEOUT')
                #raise RetryException()
            except Exception:
                self.logger.exception(f'DIGFAIL ({self.next_ooi_obj.ooi}): {traceback.format_exception(*sys.exc_info())}')
                query = DNSRequest.DNSQuery(status='DIGFAIL')
            else:
                try:
                    response_data = data[0]
                    if response_data.get('status', '') == 'SERVFAIL':
                        servfail += 1
                        query = DNSRequest.DNSQuery(status='SERVFAIL')
                        if self.scanning_request.with_dnssec:
                            cmd_list.append('+cdflag')
                    else:
                        query = DNSRequest.DNSQuery().build_response(response_data,
                                                                     scanner=self,
                                                                     evaluation_settings=self.scanner_document.evaluation,
                                                                     ooi=self.next_ooi_obj.ooi,
                                                                     katti_meta_data=self.meta_data_as_son)
                except Exception:
                    self.logger.exception(f'{traceback.format_exception(*sys.exc_info())}')
                    query = DNSRequest.DNSQuery(status='NOVALIDRESPONSE')
            finally:
                self.scanning_result.query_counter += 1
                query.nameserver_ip = next_name_server
                self.scanning_result.queries.append(query)

            match query.status:
                case 'NOERROR' if servfail >= 1 and self.scanning_request.with_dnssec:
                    self.scanning_result.dnssec_failed = True
                    break
                case 'NOERROR' if servfail >= 1:
                    break

                case 'SERVFAIL' if servfail > 1 and self.scanning_request.dig_type == 'ANY'\
                                   and not self.scanning_request.ignore_fail and not self.next_ooi_obj.any_failed_origin_id:
                    for record_type in self._backup_records:
                        self.scanning_request.oois.append(DomainForDNS(raw_ooi=self.next_ooi_obj.ooi,
                                                                       any_failed_origin_id=self.scanning_result.id,
                                                                       any_failed_dig_type=record_type))
                    break

                case 'SERVFAIL' if servfail > 1:
                    break
                case 'SERVFAIL' if servfail <= 1 and self.scanning_request.with_dnssec: #dnssec == 1 and first run or no dnssec
                    continue
                case 'SERVFAIL':
                    pass

                case 'NOERROR' if self.scanning_request.dig_type == 'ANY' and len(query.records) == 1 and query.records[0].fetch().record_type == 'HINFO' and not self.next_ooi_obj.any_failed_origin_id :
                    for record_type in self._backup_records:
                        self.scanning_request.oois.append(DomainForDNS(raw_ooi=self.next_ooi_obj.ooi,
                                                                       any_failed_origin_id=self.scanning_result.id,
                                                                       any_failed_dig_type=record_type))
                    break

                case 'NXDOMAIN' | 'NOERROR' | 'NOTIMP' | 'REFUSED':
                    break
            next_name_server = name_servers.pop(0) if len(name_servers) > 0 else None
            if next_name_server:
                if self.scanning_request.with_dnssec:
                    cmd_list = ['dig', '+dnssec', f'@{next_name_server}', f'{self.next_ooi_obj.ooi}', self._dig_type]
                else:
                    cmd_list = ['dig', f'@{next_name_server}', f'{self.next_ooi_obj.ooi}', self._dig_type]
            else:
                break
