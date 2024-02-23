import datetime
from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import AbstractDynamicalDocument
from mongoengine import StringField


class KattiServiceDB(AbstractDynamicalDocument):
    meta = {'allow_inheritance': True,
            'collection': 'KattiServices'}

    service_name = StringField(required=True, unique=True)

    _last_reload = datetime.datetime.utcnow()

    def reload_args(self, reload_interval=60, force_reload=False, no_reload=False, fields_to_reload=[]):
        if not no_reload and (force_reload or (not self._last_reload or (datetime.datetime.utcnow() - self._last_reload).total_seconds() > reload_interval)):
            self.reload(*fields_to_reload)
            self._last_reload = datetime.datetime.utcnow()

