import datetime
from bson import ObjectId, SON
from mongoengine import StringField, BooleanField, LazyReferenceField, IntField, \
    DateTimeField, EmbeddedDocumentField, DynamicField, EmbeddedDocumentListField, ObjectIdField, DoesNotExist
from pymongo import UpdateOne
from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import AbstractNormalDocument, AbstractDynamicalDocument
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.Tag import MetaData, Ownership
from katti.KattiUtils.Exceptions.ScannerExceptions import BackpropagationNotSupported


def get_last_valid_result(result_cls, ooi: str, scanner_id: ObjectId, ttl: int):
    return result_cls.objects(ooi=ooi,
                              scanner=scanner_id,
                              id__gte=ObjectId.from_datetime(
                                  (datetime.datetime.utcnow() - datetime.timedelta(seconds=ttl)))).modify(
        inc__access_counter=1, upsert=False)


class ErrorParking(AbstractDynamicalDocument):
    meta = {'collection': 'scanner_error_parking'}


class BaseScannerDocument(AbstractNormalDocument):
    meta = {'collection': 'scanner',
            'allow_inheritance': True}

    scanner_type = StringField(required=True)
    active = BooleanField(default=True)
    time_valid_response = IntField(default=24 * 60 * 60)
    max_wait_time_for_cache = IntField(default=5)
    name = StringField(required=True, unique=True)
    fast_api_daily_quota = IntField(default=0)
    default_scanner = BooleanField(default=False)

    @classmethod
    def support_backpropagation(cls) -> bool:
        return cls.get_backward_propagation_results is not cls.__base__.get_backward_propagation_results

    @staticmethod
    def get_backward_propagation_results(result_ids: list[ObjectId]) -> list[dict]:
        return BackpropagationNotSupported()

    @staticmethod
    def get_scanner_id(scanner_name) -> ObjectId | None:
        try:
            return BaseScannerDocument.objects.get(name=scanner_name).only('id').id
        except DoesNotExist:
            return None

    @staticmethod
    async def get_scanner_id(scanner_name, db_object):
        x = db_object[BaseScannerDocument._meta['collection']].find_one({'name': scanner_name})
        if x:
            return x['_id']
        return None

    @classmethod
    def get_default_scanner_id(cls):
        return cls.objects.only('id').get(default_scanner=True).id

    @classmethod
    async def async_get_default_scanner_id(cls, db_object):
        x = await db_object[cls._meta['collection']].find_one({'_cls': f'{cls.__base__.__name__}.{cls.__name__}',
                                                               'default_scanner': True})
        if not x:
            raise DoesNotExist()
        return x['_id']


class BaseScanningRequests(AbstractDynamicalDocument):
    meta = {'abstract': True}
    ownership = EmbeddedDocumentField(Ownership, required=True)
    scanner = LazyReferenceField(BaseScannerDocument, required=True)
    ooi = DynamicField(required=True)
    katti_meta_data = EmbeddedDocumentListField(MetaData)
    katti_create = DateTimeField()
    quota_exception = StringField(default=None)

    def __init__(self, *args, **kwargs):
        if self._update_sub_documents.__func__ is BaseScanningRequests._update_sub_documents or self._get_complete_sub_doc_results.__func__ is BaseScanningRequests._get_complete_sub_doc_results:
            raise AttributeError(
                'Methods _update_sub_documents or/and _get_complete_sub_doc_results are not overriden.')
        super().__init__(*args, **kwargs)

    @classmethod
    def build_new_request(cls, ooi, scanner, ownership, meta_data=None, **kwargs):
        if meta_data is None:
            meta_data = []
        else:
            meta_data = [meta_data]
        new_re = cls(katti_create=datetime.datetime.utcnow(), ooi=ooi, scanner=scanner, katti_meta_data=meta_data,
                     ownership=ownership, **kwargs)
        return new_re

    def update_exiting_request_in_db(self, new_meta_data_as_SON: SON):
        self.__class__.objects(id=self.id).modify(add_to_set__katti_meta_data=new_meta_data_as_SON)
        self._update_sub_documents(new_meta_data_as_SON)

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        raise NotImplementedError()

    def _get_complete_sub_doc_results(self, I: dict):
        raise NotImplementedError()

    def get_complete_result(self) -> dict:
        I = self.to_mongo().to_dict()
        self._get_complete_sub_doc_results(I)
        return I


class BaseScanningResults(AbstractDynamicalDocument):
    meta = {'abstract': True}

    katti_create = DateTimeField()
    katti_last = DateTimeField()
    ooi = StringField()
    scanner = ObjectIdField()
    katti_meta_data = EmbeddedDocumentListField(MetaData)

    @classmethod
    def get_result_from_db(cls, scanner_obj, filter: dict, ooi, update=None, set_on_insert_dict: dict = None,
                           with_scanner_id=False, katti_meta_data: SON | None = None, only_id=False):

        final_update = BaseScanningResults._build_update_dict(scanner_obj, update, ooi, set_on_insert_dict,
                                                              with_scanner_id=with_scanner_id,
                                                              katti_meta_data=katti_meta_data)
        if only_id:
            return cls.objects(__raw__=filter).only('id').modify(__raw__=final_update,
                                                                 upsert=True,
                                                                 new=True)
        else:
            return cls.objects(__raw__=filter).modify(__raw__=final_update,
                                                      upsert=True,
                                                      new=True)

    @staticmethod
    def build_update_one(scanner_obj, filter: dict, ooi, update=None, set_on_insert_dict: dict = None,
                         with_scanner_id=True) -> (ObjectId, UpdateOne):
        final_update = BaseScanningResults._build_update_dict(scanner_obj, update, ooi, set_on_insert_dict,
                                                              with_scanner_id=with_scanner_id)
        id = ObjectId()
        BaseScanningResults._expand_update(update_key='$setOnInsert',
                                           update={'_id': id}, mongodb_update=final_update)
        return id, UpdateOne(filter=filter, update=final_update, upsert=True)

    @staticmethod
    def _build_update_dict(scanner_obj, update, ooi, set_on_insert_dict, with_scanner_id=True,
                           katti_meta_data: SON | None = None):
        if update is None:
            update = {}
        BaseScanningResults._expand_update(update_key='$set',
                                           update={'katti_last': datetime.datetime.utcnow()},
                                           mongodb_update=update)
        BaseScanningResults._expand_update(update_key='$setOnInsert',
                                           update={'katti_create': datetime.datetime.utcnow()}, mongodb_update=update)
        if with_scanner_id:
            BaseScanningResults._expand_update(update_key='$setOnInsert',
                                               update={'scanner': scanner_obj.scanner_document.id},
                                               mongodb_update=update)
        if ooi:
            BaseScanningResults._expand_update(update_key='$setOnInsert',
                                               update={'ooi': str(ooi)}, mongodb_update=update)
        if katti_meta_data:
            BaseScanningResults._expand_update(update_key='$addToSet',
                                               update={'katti_meta_data': katti_meta_data}, mongodb_update=update)
        if set_on_insert_dict:
            BaseScanningResults._expand_update(update_key='$setOnInsert',
                                               update=set_on_insert_dict, mongodb_update=update)
        return update

    @staticmethod
    def _expand_update(update_key, update: dict, mongodb_update: dict):
        if update_key in mongodb_update:
            mongodb_update[update_key].update(update)
        else:
            mongodb_update.update({update_key: update})
