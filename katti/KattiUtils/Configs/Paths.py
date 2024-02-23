import os


KATTI_EXTENSIONS_REPO = os.path.expanduser('~/katti_extensions')
KATTI_I_AM_HOME_FLAG = os.path.expanduser('~/katti_home')
KATTI_CONFIG_FILES_REPO = os.path.expanduser('~/katti/katti_config')
KATTI_CORE_REPO = os.path.expanduser('~/katti_core')


KATTI_DATABASE_CONFIG = os.path.join(KATTI_CONFIG_FILES_REPO, 'database_configs.yml')
KATTI_CELERY_CONFIG = os.path.join(KATTI_CONFIG_FILES_REPO, 'celery.yml')
KATTI_DOCKER_CONFIG = os.path.join(KATTI_CONFIG_FILES_REPO, 'docker.yml')
KATTI_SCANNER_CONFIG = os.path.join(KATTI_CONFIG_FILES_REPO, 'scanner.yml')
KATTI_ENV_CONFIG = os.path.join(KATTI_CONFIG_FILES_REPO, 'env.yml')


MAIN_DIR = os.path.expanduser('~/')






