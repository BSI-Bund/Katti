import os
from katti.KattiUtils.Configs.ConfigHolder import get_config_holder

LONG_TERM_TASK_RESTART = lambda: get_config_holder().get_config_value('long_term_task_restart')
CRAWLING_REQUEST_CACHE_TIME = lambda: get_config_holder().get_config_value('crawling_request_cache_time')
CRAWLING_CONFIG_CACHE_TIME = lambda: get_config_holder().get_config_value('crawling_config_cache_time')
CRAWLING_DNS_PRE_TASK_EXPIRE = lambda: get_config_holder().get_config_value('crawler_dns_pre_check_task_expire')
CRAWLING_STOP_SIGNAL_MAX_WAIT_FOR_CRAWLING_TASKS = lambda: get_config_holder().get_config_value('crawling_stop_signal_max_wait_for_crawling_tasks')
CRAWLING_MAX_WAIT_FOR_URL_GENERATOR = lambda: get_config_holder().get_config_value('crawling_max_wait_for_url_generator')
CRAWLING_MIN_TASKS_PER_GROUP = lambda: get_config_holder().get_config_value('crawling_min_tasks_per_group')
SYSTEM_USER = lambda: get_config_holder().get_system_user()


SCANNING_TASK_COUNTDOWN_SCANNER_STOP = lambda: get_config_holder('scanning_task_countdown_scanner_stop')

TRIGGER_CACHE_TIME = lambda: get_config_holder('trigger_cache_time')

DEFAULT_MAIL_FOM = lambda: get_config_holder('default_mail_from')
MAIL_HOST = lambda: get_config_holder('mail_host')

#hard coded

SCANNING_TASKS_COUNTDOWN_DEFAULT = 10
DEFAULT_SYSTEM_QUEUE_PRIO = 5
CRAWLER_DEFAULT_QUEUE = 'crawler'
CRAWLER_DNS_PRE_CHECK_QUEUE = 'fast_lane'
TASK_EXECUTION_INPUT_TYPES: list[str] = ['ipv6', 'ips', 'ipv4', 'domains', 'urls', 'hash', 'object_ids', 'NaN']
KATTI_I_AM_HOME_FLAG = os.path.expanduser('~/katti_home')
