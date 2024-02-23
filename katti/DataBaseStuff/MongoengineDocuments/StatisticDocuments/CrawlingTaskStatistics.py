from katti.DataBaseStuff.MongoengineDocuments.Crawling.Bundle import SubTiming
from mongoengine import ObjectIdField, EmbeddedDocumentListField
from katti.DataBaseStuff.MongoengineDocuments.StatisticDocuments.TaskBaseStatistics import BaseTaskStatistics


class CrawlingTaskStatistics(BaseTaskStatistics):
    crawling_request_id = ObjectIdField(required=True)
    docker_webdriver_start_timings = EmbeddedDocumentListField(SubTiming)
