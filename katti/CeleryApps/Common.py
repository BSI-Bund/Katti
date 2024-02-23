import datetime
import pickle
from pymongo import UpdateOne
from katti.CeleryApps.KattiApp import katti_app
from katti.DataBaseStuff.MongoengineDocuments.Scanner.LongTermRetry import LongTermRetryTask
from katti.KattiUtils.Configs.ConfigKeys import LONG_TERM_TASK_RESTART


@katti_app.task(bind=True)
def restart_long_term_tasks(self):
    bulk = []
    for task in LongTermRetryTask.objects(next_execution__lte=datetime.datetime.utcnow(), status='pending'):
        x = pickle.loads(task.task_signature).apply_async(countdown=LONG_TERM_TASK_RESTART())
        bulk.append(UpdateOne({'_id': task.id},{'$set': {'last_changed': datetime.datetime.utcnow(), 'status': 'restarted'},
                               '$push': {'children': str(x.task_id)}}))
    if len(bulk) > 0:
        LongTermRetryTask._get_collection().bulk_write(bulk)