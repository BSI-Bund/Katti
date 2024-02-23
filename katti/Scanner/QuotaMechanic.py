import datetime
import time
from typing import Union
from bson import ObjectId
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.TimeLord import API
from katti.KattiUtils.HelperFunctions import get_today_as_datetime, i_am_at_home
from katti.RedisCacheLayer.RedisMongoCache import set_up_connection, ManualConnectionSettings


class MinuteBlockException(Exception):
    def __str__(self) -> str:
        return 'MinuteBlock'


class DayBlockException(Exception):

    def __str__(self) -> str:
        return 'DayBlock'


class QMinute(MinuteBlockException):
    pass


class QDay(DayBlockException):
    pass


class UserHasNoAccess(Exception):
    pass


class BadEndpointArguments(Exception):
    pass


class QuotaMechanic:
    def __init__(self, cache_key, manual_con_data: ManualConnectionSettings = None):
        self._redis = set_up_connection(manual=manual_con_data)
        self._cache_key: str = cache_key

    def check_minute_block(self):
        if not self._redis.get(f'quota_{datetime.datetime.utcnow().strftime("%m %d %Y %H:%M")}_{self._cache_key}'):
            return True
        else:
            raise QMinute()

    def check_day_block(self):
        if not self._redis.get(f'quota_{get_today_as_datetime()}_{self._cache_key}'):
            return True
        else:
            raise QDay()

    def set_minute_block(self):
        self._redis.set(name=f'quota_{datetime.datetime.utcnow().strftime("%m %d %Y %H:%M")}_{self._cache_key}',
                        value=f'{datetime.datetime.utcnow().strftime("%m %d %Y %H:%M:%S")}',
                        ex=60)

    def set_day_block(self):
        day_hours_left = (24 - datetime.datetime.utcnow().hour)
        self._redis.set(name=f'quota_{datetime.datetime.utcnow().strftime("%m %d %Y")}_{self._cache_key}',
                        value=f'{datetime.datetime.utcnow().strftime("%m %d %Y %H:%M:%S")}',
                        ex=(day_hours_left + 2)*3600)

    def set_remaining_quota(self, value):
        day_hours_left = (24 - datetime.datetime.utcnow().hour)
        self._redis.set(f'quota_left{get_today_as_datetime()}_{self._cache_key}', value=value,
                        ex=(day_hours_left + 2)*3600)


day_block_user_str = lambda time_lord_id, endpoint_name: f'{time_lord_id}{get_today_as_datetime()}{endpoint_name}day_block'
day_quota_user_str = lambda time_lord_id, endpoint_name: f'{time_lord_id}{get_today_as_datetime()}{endpoint_name}quota'


class QuotaUserAPI:
    def __init__(self, time_lord_id: ObjectId, redis_connection=set_up_connection()):
        self._redis = redis_connection
        self._time_lord_id = time_lord_id
        self._endpoint: API.Endpoint | None = None
        self._i_am_home = i_am_at_home()

    def inc_quota(self, endpoint_name: str, amount: int):
        return self._redis.incrby(name=day_quota_user_str(self._time_lord_id, endpoint_name),
                                  amount=amount)

    def set_endpoint(self, endpoints: list[Union[API.Endpoint, dict]], endpoint_: str):
        #TODO: Maybe not your best idea :P
        #if self._i_am_home:
        #    return
        for endpoint in endpoints:
            if isinstance(endpoint, API.Endpoint):
                if endpoint.endpoint_name == endpoint_:
                    self._endpoint = endpoint
                    return
            else:
                if endpoint['endpoint_name'] == endpoint_:
                    self._endpoint = API.Endpoint(**endpoint)
                    return
        raise UserHasNoAccess(endpoint_)

    def enough_quota(self, amount: 1 = 1):
        if self._i_am_home:
            return
        if not self._endpoint:
            raise BadEndpointArguments()
        if not self._endpoint.access:
            raise UserHasNoAccess(self._endpoint.endpoint_name)
        if self._endpoint.daily_rate == 0:
            self.inc_quota(endpoint_name=self._endpoint.endpoint_name, amount=amount)
            return
        if self._redis.get(day_block_user_str(self._time_lord_id, self._endpoint.endpoint_name)):
            raise QDay('User quota.')
        else:
            try:
                current_quota = self._redis.get(day_quota_user_str(self._time_lord_id, self._endpoint.endpoint_name))
                if isinstance(current_quota, bytes):
                    current_quota = int(current_quota)
                else:
                    current_quota = 0
                if not current_quota or (current_quota + amount <= self._endpoint.daily_rate):
                    if self.inc_quota(self._endpoint.endpoint_name, amount) == self._endpoint.daily_rate:
                        self._redis.set(day_block_user_str(self._time_lord_id, self._endpoint.endpoint_name), value=1, ex=(26 - datetime.datetime.utcnow().hour) * 3600)
                    return
                else:
                    raise QDay('User quota.')
            finally:
                try:
                    pass
                 #   quota_lock.release()
                except Exception:
                    pass
