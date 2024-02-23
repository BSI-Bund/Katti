import datetime
from katti.DataBaseStuff.MongoengineDocuments.Common.ConfigurationClasses import ConfigDatabase
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.TimeLord import TimeLord
from katti.KattiUtils.Exceptions.CommonExtensions import ExtremeFailure

config_holder = None


def get_config_holder():
    global config_holder
    if not config_holder:
        config_holder = ConfigHolder()
    return config_holder


class ConfigHolder:
    def __init__(self):
        from katti.KattiUtils.Configs.ConfigKeys import BASE_CONFIG_REFRESH_RATE
        from katti.RedisCacheLayer.RedisMongoCache import RedisMongoCache
        self._refresh_rate = BASE_CONFIG_REFRESH_RATE
        self.redis_cache = RedisMongoCache()
        self.config: ConfigDatabase = self.redis_cache.get_mongoengine_cache(cache_key='katti_config',
                                                                             mongoengine_cls=ConfigDatabase,
                                                                             mongo_filter={'_cls': ConfigDatabase()._cls},
                                                                             ttl=0)
        if not self.config:
            self.config = ConfigDatabase()
            self.config.save()
        self.last_refresh = datetime.datetime.utcnow()
        self._system_user: TimeLord | None = None

    def get_config_value(self, key):
        if (datetime.datetime.utcnow() - self.last_refresh).total_seconds() > self._refresh_rate:
            self.config = self.redis_cache.get_mongoengine_cache(cache_key='katti_config',
                                                                 mongoengine_cls=ConfigDatabase,
                                                                 mongo_filter={'_cls': ConfigDatabase()._cls},
                                                                 ttl=0)
            self.last_refresh = datetime.datetime.utcnow()
            self._system_user = None

        return getattr(self.config, key)

    def get_system_user(self):
        if not self.config:
            raise ExtremeFailure('No config class available')
        if not self._system_user:
            self._system_user = self.config.system_user
        return self._system_user
