import datetime
from bson import ObjectId
from croniter import croniter
from mongoengine import EmbeddedDocument, EmbeddedDocumentField, StringField, IntField, DateTimeField, BooleanField
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseExecutionInformation
from katti.KattiUtils.Configs.ConfigKeys import TASK_EXECUTION_INPUT_TYPES


class Task(EmbeddedDocument):
    execution_information = EmbeddedDocumentField(BaseExecutionInformation)
    task_id = StringField(required=True)
    input_type = StringField(choices=TASK_EXECUTION_INPUT_TYPES)

    def clean(self):
        if not self.task_id:
            self.task_id = str(ObjectId())


class TaskExecutionTracking(EmbeddedDocument):
    counter = IntField(min_value=0, default=0)
    last_execution = DateTimeField()
    next_execution = DateTimeField()
    task_id = StringField(required=True)
    finished = BooleanField(default=False)

    def can_we_conduct_task(self, execution_information: BaseExecutionInformation):
        return self if self.next_execution and ((execution_information.max_lookups > self.counter or execution_information.max_lookups == 0) and datetime.datetime.utcnow() >= self.next_execution) else None

    def set_and_calculate_next(self, execution_information: BaseExecutionInformation) -> None | datetime.datetime:
        time = datetime.datetime.utcnow()
        self.last_execution = time
        self.counter += 1
        if execution_information.max_lookups == 1:
            self.next_execution = None
            self.finished = True
        elif execution_information.max_lookups > self.counter or execution_information.max_lookups == 0:
            self._calculate_next_lookup_time(execution_information)
            return self.next_execution
        else:
            self.next_execution = None
            self.finished = True

    def _calculate_next_lookup_time(self, execution_information: BaseExecutionInformation):
        if execution_information.no_cron_or_int:
            self.next_execution = datetime.datetime.utcnow()
        elif execution_information.interval:
            match execution_information.interval.period:
                case 'day':
                    self.next_execution = (datetime.datetime.utcnow() + datetime.timedelta(
                        days=execution_information.interval.every))
                case 'hours':
                    self.next_execution = (
                            datetime.datetime.utcnow() + datetime.timedelta(hours=execution_information.interval.every))
                case 'minutes':
                    self.next_execution = (
                            datetime.datetime.utcnow() + datetime.timedelta(
                        minutes=execution_information.interval.every))
        else:
            iter = croniter(execution_information.cron_tab.to_string(), datetime.datetime.utcnow())
            self.next_execution = iter.get_next(datetime.datetime)
