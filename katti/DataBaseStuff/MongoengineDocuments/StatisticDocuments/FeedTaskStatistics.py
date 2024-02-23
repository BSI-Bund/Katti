from mongoengine import IntField, ObjectIdField
from katti.DataBaseStuff.MongoengineDocuments.StatisticDocuments.TaskBaseStatistics import BaseTaskStatistics


class FeedTaskStatistics(BaseTaskStatistics):
    entries_counter = IntField()
    feed_id = ObjectIdField()