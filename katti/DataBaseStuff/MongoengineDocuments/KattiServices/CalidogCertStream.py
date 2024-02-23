from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import AbstractDynamicalDocument


class CalidogCerstreamEntry(AbstractDynamicalDocument):
    meta = {'collection': 'calidog_ct_logs'}
