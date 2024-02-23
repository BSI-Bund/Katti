import ipaddress
import typing
import nmap
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.Scanner.BaseScanner import BaseScanner, OOI, BaseScanningRequestForScannerObject
from pydantic.dataclasses import dataclass
from pydantic import validator


@dataclass(config=PydanticConfig)
class IPsForShodan(OOI):
    raw_ooi = list[typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]

    @property
    def ooi(self):
        return self.raw_ooi


@dataclass(config=PydanticConfig)
class ShodanScanningRequest(BaseScanningRequestForScannerObject):

    @validator('oois')
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


class Nmap(BaseScanner):
    """
    Important: Nmap needs network privileges
    """

    @property
    def get_result_class(self) -> typing.Type[BaseScanningRequests]:
        pass

    @property
    def get_scanner_mongo_document_class(self):
        pass

    def _do_your_scanning_job(self):
        try:
            self.nm = nmap.PortScanner()
            x = self.nm.scan('127.0.0.1', '80', arguments='--privileged -sS')
        except Exception:
            pass

