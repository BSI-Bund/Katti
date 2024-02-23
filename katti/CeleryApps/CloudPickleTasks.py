import cloudpickle
from bson import ObjectId
from katti.CeleryApps.KattiApp import katti_app


@katti_app.task(bind=True)
def execute_cloud_pickle_code(self, *args, **kwargs):
    cloudpickle.loads(kwargs['cloud_pickle_code'])(*args, **kwargs)


@katti_app.task(bind=True)
def execute_shiv_app(self, name, version, app_id: ObjectId | None, cache_key_raw_app: str | None = None, *args, **kwargs):
    pass

