import sys
import traceback
import typing
import whois

from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    WhoisExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.KattiUtils.HelperFunctions import is_valid_domain, is_ip_addr_valid
from pydantic import field_validator
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.DataBaseStuff.MongoengineDocuments.Scanner.WhoisDB import WhoisDB, WhoisRequestDB, WhoisResult
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI


@dataclass(config=PydanticConfig)
class WhoisOOI(OOI):
#TODO: Timeout
    @field_validator('raw_ooi')
    def validate_ooi(cls, v):
        if not is_valid_domain(v) and not is_ip_addr_valid(v):
            raise ValueError('Only domains and IPs are allowed.')
        else:
            return v


@dataclass(config=PydanticConfig)
class WhoisRequest(BaseScanningRequestForScannerObject):
    whois_server: str | None = None

    @staticmethod
    def ooi_cls():
        return WhoisOOI

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [WhoisOOI(raw_ooi=domain_or_ip) for domain_or_ip in raw_oois]

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        match ooi_type:
            case 'ips' | 'ipv4' | 'ipv6' | 'domain':
                return True
            case _:
                return False


class Whois(BaseScanner):
    _db_document: WhoisRequestDB
    scanning_request: WhoisRequest

    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import whois_celery
        return [WhoisOOI, whois_celery]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        super().pre_defined_config_for_ooi_type(scanner_name, ooi_type)

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return WhoisExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'whois'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return WhoisDB(**config)

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return WhoisRequestDB

    @staticmethod
    def get_scanner_mongo_document_class():
        return WhoisDB

    def _do_your_scanning_job(self):
        try:
            domain_whois = whois.query(domain=self.next_ooi_obj.ooi,
                                       force=True,
                                       server=self.scanning_request.whois_server)
            x_dict = domain_whois.__dict__
            del x_dict['name']
            whois_result = WhoisResult.get_result_from_db(scanner_obj=self,
                                                          filter={'ooi': self.next_ooi_obj.ooi,
                                                                  'last_updated': x_dict.pop('last_updated')},
                                                          ooi=None,
                                                          set_on_insert_dict=x_dict,
                                                          only_id=True)
            self.scanning_result.result = whois_result
        except AttributeError:
            self.scanning_result.error = 'Not found.'
        except Exception:
            self.logger.error(traceback.format_exception(*sys.exc_info()))
            self.scanning_result.error = 'Unknown'
