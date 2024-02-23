import yaml
from katti.KattiUtils.Configs.Paths import KATTI_ENV_CONFIG
from katti.KattiUtils.Exceptions.CommonExtensions import ApiKeyNameIsUnknown


class ReadConfigWithSecrets:
    def __init__(self):
        with open(KATTI_ENV_CONFIG) as file:
            self._secrets_config = yaml.safe_load(file)
        if not self._secrets_config:
            self._secrets_config = {}

    def _api_key_loader_str(self, loader: yaml.SafeLoader, node: yaml.nodes.MappingNode):
        """Construct an employee."""
        key_name = loader.construct_scalar(node)
        if key_name in self._secrets_config:
            return self._secrets_config[key_name]
        raise ApiKeyNameIsUnknown()

    def _get_loader(self):
        """Add constructors to PyYAML loader."""
        loader = yaml.SafeLoader
        loader.add_constructor("!API-KEY", self._api_key_loader_str)
        loader.add_constructor("!IS-IP", self._api_key_loader_str)
        loader.add_constructor("!IS-PORT", self._api_key_loader_str)
        loader.add_constructor("!USER", self._api_key_loader_str)
        return loader

    def read_config_with_secrets(self, config_path):
        with open(config_path) as file:
            return yaml.load(file.read(), self._get_loader())