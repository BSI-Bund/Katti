from enum import Enum
from functools import partial

from katti.CeleryApps.Workflows.WorkflowBuilderFunc import dns_to_ip_scanner_workflow_builder


class BuilderMapping(Enum):
    dns_to_ip_scanner_workflow = partial(dns_to_ip_scanner_workflow_builder)