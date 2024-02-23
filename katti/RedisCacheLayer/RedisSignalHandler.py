from bson import  ObjectId

from katti.RedisCacheLayer.RedisMongoCache import set_up_connection

class RedisSignalHandling:
    STOP = 'stop'
    DONE = 'done'
    ERROR = 'error'
    START = 'start'
    REPORT_IN_PROGRESS = 'report_progress'

    def __init__(self, signal_id: str, connection=None):
        self._connection = connection if connection else set_up_connection()
        self._redis_lock = None
        self._signal_id: str = signal_id

    def set_signal(self, signal: str, ex=60):
        self._connection.set(name=f'{self._signal_id}{signal}', value=str(ObjectId()), ex=ex)

    def delete_signal(self, signal: str):
        self._connection.delete(f'{self._signal_id}{signal}')

    def get_signal(self, signal):
        x = self._connection.get(f'{self._signal_id}{signal}')
        if not x:
            return False
        else :
            return True

    def get_signal_with_value(self, signal):
        return self._connection.get(f'{self._signal_id}{signal}')

    def reset(self, signals= ['stop', 'start']):
        for signal in signals:
            self.delete_signal(signal)

