import json
import os.path
import pickle
import requests
import yaml
from cryptography.fernet import Fernet
from pydantic import Field
from pydantic.dataclasses import dataclass
from katti.KattiUtils.Configs.Paths import KATTI_DATABASE_CONFIG, \
    KATTI_CELERY_CONFIG, KATTI_DOCKER_CONFIG
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.KattiUtils.Exceptions.CommonExtensions import ExtremeFailure

DATBASE_CONFIG_OBJC = None

env_vars = {}

master_config = None

def set_up_env_vars():
    for key, value in dict(os.environ).items():
        if 'KATTI' in key:
            key = key.replace('KATTI_', '')
            key = key.lower()
            env_vars.update({key: value})


def get_env_vars():
    return env_vars




@dataclass(config=PydanticConfig)
class Redis:
    user: str
    port: int
    password: str
    host: str


@dataclass(config=PydanticConfig)
class DatabaseConfigs:
    mongodb_configs: dict[str, str]  # MongoDsn doesn't work
    redis: Redis

    @classmethod
    def get_config(cls):
        global DATBASE_CONFIG_OBJC
        if not DATBASE_CONFIG_OBJC:
            try:
                print(KATTI_DATABASE_CONFIG)
                with open(KATTI_DATABASE_CONFIG, 'r') as raw_file:
                    config = yaml.safe_load(raw_file)
                    DATBASE_CONFIG_OBJC = cls(redis=Redis(**config['redis']), mongodb_configs=config['mongodb'])
            except FileNotFoundError:
                    pass
        return DATBASE_CONFIG_OBJC

    @property
    def redis_url(self):
        return f'redis://{self.redis.user}:{self.redis.password}@{self.redis.host}:{self.redis.port}'

    def get_mongodb_uri_for_user(self, user='katti'):
        return self.mongodb_configs[user]


@dataclass(config=PydanticConfig)
class CeleryConfig:
    broker: str
    task_serializer: str
    result_serializer: str
    accept_content: list[str]
    redis_db_nr: int

    @classmethod
    def get_config(cls):
        try:
            with open(KATTI_CELERY_CONFIG, 'r') as raw_file:
                config_file = yaml.safe_load(raw_file)
                return cls(**config_file)
        except FileNotFoundError:
            pass

@dataclass(config=PydanticConfig)
class ImageCFG:
    image_name: str
    args: dict = Field(default_factory=dict)


@dataclass(config=PydanticConfig)
class Docker:
    docker_host: str
    start_args: dict = Field(default_factory=dict)
    crawler_cfg: ImageCFG | None = None
    service_cfg: ImageCFG | None = None

    @classmethod
    def get_config(cls):
        with open(KATTI_DOCKER_CONFIG, 'r') as raw_file:
            config_file = yaml.safe_load(raw_file)
            new_ = cls(docker_host=config_file['docker_host'])
            new_.service_cfg = ImageCFG(**config_file['service_cfg']) if 'service_cfg' in config_file else None
            new_.crawler_cfg = ImageCFG(**config_file['crawler_cfg']) if 'crawler_cfg' in config_file else None
            return new_


