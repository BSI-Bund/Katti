import typing
from bson import SON
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, BaseScannerDocument
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI
from pydantic.dataclasses import dataclass
from mongoengine import StringField
from katti.Scanner.QuotaMechanic import MinuteBlockException, DayBlockException


class TestScannerDB(BaseScannerDocument):
    katti = StringField()


class TestRequestDB(BaseScanningRequests):
    meta = {'collection': 'test_request'}

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        pass

    def _get_complete_sub_doc_results(self, I: dict):
        return I


@dataclass(config=PydanticConfig)
class TestOOI(OOI):
    pass

@dataclass(config=PydanticConfig)
class TestRequest(BaseScanningRequestForScannerObject):

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [TestOOI(raw_ooi=ooi) for ooi in raw_oois]

    @property
    def endpoint_name(self) -> str:
        return 'test_scanner'

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def ooi_cls():
        return TestOOI


class TestScanner(BaseScanner):

    @property
    def get_result_class(self) -> typing.Type[BaseScanningRequests]:
        return TestRequestDB

    @property
    def get_scanner_mongo_document_class(self):
        return TestScannerDB

    def _do_your_scanning_job(self):
        self.scanning_result.test = True
        match self.next_ooi_obj.ooi:
            case 'minute':
                self.retry_args.update({'countdown': 5})
                raise MinuteBlockException()
            case 'minute_1' if self._task.request.retries == 0:
                self.retry_args.update({'countdown': 5})
                raise MinuteBlockException()
            case 'day':
                self.retry_args.update({'countdown': 5})
                raise DayBlockException()
            case 'day_1' if self._task.request.retries == 0:
                self.retry_args.update({'countdown': 5})
                raise DayBlockException()