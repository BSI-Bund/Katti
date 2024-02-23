from bson import ObjectId
from mongoengine import StringField
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument
from katti.DataBaseStuff.MongoengineDocuments.Scanner.VirusTotalScanningRequestResult import VirusTotalScanningRequest


class VirusTotalConfig(BaseScannerDocument):
    api_key = StringField(required=True)
    vt_user = StringField(required=True)
