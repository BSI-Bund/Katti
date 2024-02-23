import datetime
from bson import SON, ObjectId
from mongoengine.fields import dateutil, DateTimeField
from mongoengine import StringField, LazyReferenceField, ListField
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument, BaseScanningRequests, BaseScanningResults


class ShodanScannerDB(BaseScannerDocument):

    api_key = StringField(required=True)



class ShodanBaseResult(BaseScanningResults):
    meta = {'collection': 'shodan_results', 'allow_inheritance': True,
            'indexes': [{'fields': ['hash_str'],
                         'cls': False}]}


class ShodanCrawlerResult(ShodanBaseResult):
    hash_str = StringField(required=True)


class ShodanMeta(ShodanBaseResult):
    hash_str = StringField(required=True)


class SubResults(ShodanBaseResult):
    ip = StringField()
    crawler_results = ListField(LazyReferenceField(ShodanCrawlerResult), default=None)
    shodan_meta = LazyReferenceField(ShodanMeta)
    shodan_last_update = DateTimeField()
    ttl = DateTimeField()
    api_error = StringField(default=None)


class ShodanScanRequest(BaseScanningRequests):
    meta = {'collection': 'shodan_requests'}
    results = ListField(LazyReferenceField(SubResults))
    api_error = StringField(default=None)

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        ids = []
        for result in self.results:
            if result.crawler_results:
                ids.extend([x.id for x in result.crawler_results])
            if result.shodan_meta:
                ids.append(result.shodan_meta.id)
        if len(ids) > 0:
            ShodanBaseResult.objects(id__in=ids).update(add_to_set__katti_meta_data=new_meta_data_as_SON)

    def _get_complete_sub_doc_results(self, I: dict):
        new_results = []
        for result in I['results']:
            result = SubResults.objects.as_pymongo().get(id=result)
            if result.get('crawler_results'):
                result.update({'crawler_results': list(
                    ShodanBaseResult.objects(id__in=[x for x in result['crawler_results']]).as_pymongo())})
            if result.get('shodan_meta'):
                result.update({'shodan_meta': ShodanMeta.objects.as_pymongo().get(id=result['shodan_meta'])})
            new_results.append(result)
        I.update({'results': new_results})


def traverse_result(value, key=""):
    if isinstance(value, dict):
        return {key: traverse_result(value, key) for key, value in value.items()}
    elif isinstance(value, list):
        return [traverse_result(item) for item in value]
    match key:
        case 'serial':
            try:
                result = {'as_hex': hex(value), 'as_str': str(value)}
            except Exception:
                result = value
            return result
        case "timestamp" | "issued" | "expires" | "last_update":
            try:
                if isinstance(value, str):
                    result = dateutil.parser.parse(value)
                elif isinstance(value, int):
                    result = datetime.datetime.fromtimestamp(value)
                else:
                    result = value
            except Exception:
                result = value
            return result
        case _ if isinstance(value, int) and value > 9223372036854775807:
            return str(value)
        case _ if isinstance(value, str):
            try:
                return value.encode(errors='ignore').decode()
            except UnicodeError:
                return 'UnicodeError'
        case _:
            return value
