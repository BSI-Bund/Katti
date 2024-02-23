from bson import SON, ObjectId
from mongoengine import StringField, IntField, ListField, LazyReferenceField, DictField
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument, \
    BaseScanningRequests, BaseScanningResults


class MaxMindOfflineDB(BaseScannerDocument):
    docker_ip = StringField(required=True)
    docker_port = IntField(required=True)
    license_key = StringField(required=True)



class MaxMindResult(BaseScanningResults):
    meta = {'collection': 'max_mind_results', 'allow_inheritance': True}
    hash_str = StringField()

class MaxMindResultCountryCity(MaxMindResult):
    city = DictField()
    continent = DictField()
    country = DictField()
    location = DictField()
    postal = DictField()
    registered_country = DictField()
    represented_country = DictField()
    subdivisions = ListField(DictField())
    traits = DictField()


class MaxMindResultASN(MaxMindResult):
    autonomous_system_number = IntField()
    autonomous_system_organization = StringField()

    prefix_len = IntField()


class MaxMindOfflineRequest(BaseScanningRequests):
    meta = {'collection': 'max_mind_requests'}
    db_type = StringField()
    errors = ListField(default=None)
    asn = LazyReferenceField(MaxMindResultASN)
    city_country = LazyReferenceField(MaxMindResultCountryCity)

    def add_error(self, error_ip: dict):
        if not self.errors:
            self.errors = [error_ip]
        else:
            self.errors.append(error_ip)

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        try:
            MaxMindResult.objects(id=self.asn.id).modify(add_to_set__katti_meta_data=new_meta_data_as_SON)
        except AttributeError:
            pass
        try:
            MaxMindResult.objects(id=self.asn.id).modify(add_to_set__katti_meta_data=new_meta_data_as_SON)
        except AttributeError:
            pass

    def _get_complete_sub_doc_results(self, I: dict):
        if I.get('asn'):
            I.update({'asn': MaxMindResultASN.objects.as_pymongo().get(id=I['asn'])})
        if I.get('city_country'):
            I.update({'city_country': MaxMindResultCountryCity.objects.as_pymongo().get(id=I['city_country'])})

