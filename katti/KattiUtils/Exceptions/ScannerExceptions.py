class RetryException(Exception):
    pass


class LongTermRetryException(Exception):
    pass


class OfflineModeNoResult(Exception):
    pass


class APIErrorException(Exception):
    text = 'Error'


class NotValidOOIException(Exception):
    pass


class NoIPv4(Exception):
    pass


class BackpropagationNotSupported(Exception):
    pass