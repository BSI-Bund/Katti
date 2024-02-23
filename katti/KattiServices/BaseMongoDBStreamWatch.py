import json
import sys
import time
import traceback
from bson import ObjectId
from mongoengine import get_db
from pymongo.change_stream import CollectionChangeStream
from katti.KattiServices.BaseKattiSerivce import BaseKattiService


class BaseMongoDBStreamWatch(BaseKattiService):

    def _next_control_round(self):
        db_ = get_db('Katti')
        self.logger.info(f'pipline is: {self.env_vars["pipeline"].replace("<d>", "$")}')
        self._pipline = self._traverse_pipline(json.loads(self.env_vars["pipeline"].replace("<d>", "$")))

        try:
            with db_[self.env_vars['collection']].watch(self._pipline) as stream:
                self._handle_stream(stream)
        except:
            self.docker_status = 'unhealthy'
            self.docker_health_api_server.set_status(self.docker_status)
            self.logger.error(traceback.format_exception(*sys.exc_info()))
        finally:
            self.logger.debug(f'Winter is coming.')

    def _handle_stream(self, stream_obj: CollectionChangeStream):
        while stream_obj.alive:
            self.set_heartbeat_reload()
            change = stream_obj.try_next()
            if change:
                self._handle_change_stream(change)
            if self.is_stop:
                break
            self._next_round_without_change()
            time.sleep(0.2)

    def _traverse_pipline(self, value, key=""):
        if isinstance(value, dict):
            return {key: self._traverse_pipline(value, key) for key, value in value.items()}
        elif isinstance(value, list):
            return [self._traverse_pipline(item) for item in value]
        if isinstance(value, str) and '$oid' in value:
            return ObjectId(value.split('_')[1])
        else:
            return value

    def _next_round_without_change(self):
        pass

    def _handle_change_stream(self, change):
        raise NotImplementedError

    def shutdown(self):
        super().shutdown()

    def _init(self):
        super()._init()


    def prepare_service(self):
        super().prepare_service()