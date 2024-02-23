import datetime
import pickle
from types import NoneType

import redis
from pydantic import Field
from pydantic.dataclasses import dataclass
from katti.KattiUtils.Configs.ConfigurationClass import DatabaseConfigs
from bson import ObjectId
from katti.KattiUtils.Exceptions.RedisCacheExceptions import CacheFailure
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig

REDIS_CONNECTION: redis.Redis | None = None


@dataclass(config=PydanticConfig)
class ManualConnectionSettings:
    host: str
    port: int
    password: str
    user: str | None = None




def set_up_connection(manual: ManualConnectionSettings | None = None) -> redis.Redis:
    global REDIS_CONNECTION
    if not REDIS_CONNECTION:
        x = manual if manual else DatabaseConfigs.get_config().redis
        REDIS_CONNECTION = redis.Redis(host=x.host, username=x.user if not x.user == '' else None, port=x.port,
                                       password=x.password)
    return REDIS_CONNECTION


def disconnect_redis():
    global REDIS_CONNECTION
    if REDIS_CONNECTION:
        try:
            REDIS_CONNECTION.close()
        except:
            pass

class RedisMongoCache:
    def __init__(self, manual_con_data: ManualConnectionSettings = None):
        self._connection = set_up_connection(manual=manual_con_data)
        self._redis_lock = None

    @property
    def redis_connection(self):
        return REDIS_CONNECTION

    def set_stop_signal(self, signal_id: str, set=True):
        self.insert_value_pair(key=f'stop_signal_{signal_id}', value=str(set))

    def is_stop_signal_set(self, signal_id: str):
        if not self.get_value(f'stop_signal_{signal_id}'):
            return False
        return True

    def delete(self, key):
        self._connection.delete(key)

    def get_value(self, key: str, if_none = None, do_pickle: bool= False):
        x = self._connection.get(key)
        if not x:
            x = if_none
        elif do_pickle:
            x = pickle.loads(x)
        return x

    def insert_value_pair(self, key, value, ttl: int=0):
        if ttl <= 0:
            self._connection.set(key, value)
        else:
            self._connection.set(key, value, ex=ttl)

    def setnx_value_pair(self, key, value):
        return self._connection.setnx(key, value)


    def get_mongoengine_cache(self, cache_key: str, mongoengine_cls, mongo_filter=None, ttl=10*60, as_son=False):
        try:
            object_as_dict = self.get_value(key=cache_key)
            if object_as_dict and not as_son:
                x = mongoengine_cls._from_son(pickle.loads(object_as_dict))
                return x
            elif object_as_dict:
                return pickle.loads(object_as_dict)
            if not isinstance(mongo_filter, NoneType):
                x = list(mongoengine_cls.objects(**mongo_filter).limit(1).order_by('-id').as_pymongo())
                if len(x) == 0:
                    return None
                self.insert_value_pair(key=cache_key, value=pickle.dumps(x[0]), ttl=ttl)
                return mongoengine_cls._from_son(x[0]) if not as_son else x[0]
            else:
                return None
        except Exception as e:
            raise CacheFailure(e)


    def set_mongoengine_object(self, mongoengine_object, cache_key, ttl=180):
        self.insert_value_pair(key=cache_key, value=pickle.dumps(mongoengine_object.to_mongo()), ttl=ttl)

    def save_mongoengine_object_and_set_cache(self, mongoengine_obj, cache_key, ttl=0):
        mongoengine_obj.save()
        self.set_mongoengine_object(mongoengine_obj, cache_key, ttl)
