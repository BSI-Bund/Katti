from mongoengine import ObjectIdField, IntField, EmbeddedDocumentListField, EmbeddedDocument, StringField, DynamicField
from katti.DataBaseStuff.MongoengineDocuments.StatisticDocuments.TaskBaseStatistics import BaseTaskStatistics


class ScannerTaskStats(BaseTaskStatistics):
    class SingleScannerStats(EmbeddedDocument):
        duration_micro_secs = IntField(required=True)
        ooi = DynamicField(required=True)


    single_scan_ooi_stats = EmbeddedDocumentListField(SingleScannerStats)
    scanner_task = StringField(required=True)
    ooi_count = IntField(min_value=0, default=0)
    ooi_left_over = IntField(min_value=0, default=0)
    scanner_id = ObjectIdField(required=True)


