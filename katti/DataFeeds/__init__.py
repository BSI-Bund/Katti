from abc import ABCMeta

class FeedRegistryBase(ABCMeta):

    REGISTRY = {}
    def __new__(cls, name, bases, attrs):
        new_cls = super().__new__(cls, name, bases, attrs)
        cls.REGISTRY[new_cls.__name__] = new_cls
        return new_cls

    @classmethod
    def get_registry(cls):
        return dict(cls.REGISTRY)


def load_all_feed_cls():
    from katti import DataFeeds
    import inspect
    import os
    import importlib
    xe = 'katti.DataFeeds'
    feed_pkg_path = os.path.dirname(inspect.getfile(DataFeeds))
    for x in os.walk(feed_pkg_path):
        next_file = x[0].split('/')[-1]
        if next_file == '__pycache__':
            continue
        for file in x[2]:
            if '.py' in file:
                try:
                    importlib.import_module(f'{xe}.{next_file}.{file.replace(".py", "")}')
                except (ModuleNotFoundError, ImportError) as e:
                    pass
