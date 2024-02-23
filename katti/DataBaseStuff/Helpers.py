import datetime
import motor.motor_asyncio
from bson import ObjectId
from pymongo import ReturnDocument, InsertOne
from pymongo.errors import BulkWriteError


def execute_bulk_ops(bulk_ops: list, collection, min_ops=100, force=False, ignore_bulk_error=False, bulk_error_handler = None) -> list:
    if len(bulk_ops) <= 0:
        return bulk_ops
    if force or len(bulk_ops) >= min_ops:
        try:
            collection.bulk_write(bulk_ops, ordered=False)
        except BulkWriteError as e:
            if bulk_error_handler:
                bulk_error_handler(e)
            if not ignore_bulk_error:
                raise
        return []
    else:
        return bulk_ops


async def save_mongoengine_objc_async(mongoengine_obj, db: motor.motor_asyncio.AsyncIOMotorClient, collection_name: str):
    if not mongoengine_obj.id:
        mongoengine_obj.id = ObjectId()
    await db[collection_name].insert_one(mongoengine_obj.to_mongo())


async def insert_bulk_mongoengine_objc_async(mongoengine_objs: list, db: motor.motor_asyncio.AsyncIOMotorClient, collection_name: str):
    bulk_updates = [InsertOne(x.to_mongo()) for x in mongoengine_objs]
    await db[collection_name].bulk_write(bulk_updates)


async def async_update_mongoengine(monoengine_cls, db: motor.motor_asyncio.AsyncIOMotorClient, collection_name, filter, update, new=True):
    x = await db[collection_name].find_one_and_update(filter, update, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE, upsert=True)
    x.update({'id': x.pop('_id')})
    return monoengine_cls(**x) if x else None


async def get_mongoengine_object_async(mongoengine_cls, db: motor.motor_asyncio.AsyncIOMotorClient, collection_name: str, filter=None):
    if filter is None:
        filter = {}
    x = await db[collection_name].find_one(filter)
    x.update({'id': x.pop('_id')})
    return mongoengine_cls(**x)


async def get_async_cursor_bundle_for_crawling_request(crawling_request_id: ObjectId, db: motor.motor_asyncio.AsyncIOMotorClient,
                                                       projection=None) -> motor.motor_asyncio.AsyncIOMotorCursor:
    if projection is None:
        projection = {}
    return db['bundles'].find({'crawling_meta_data.crawling_request_id': crawling_request_id}, projection)


async def async_execute_bulk_ops(bulk_ops: list, db: motor.motor_asyncio.AsyncIOMotorClient, collection_name: str, force: bool=False, min_ops: int=0):
    if len(bulk_ops) <= 0:
        return bulk_ops
    if force or len(bulk_ops) >= min_ops:
        await db[collection_name].bulk_write(bulk_ops)
        return []
    return bulk_ops




def get_array_update_pipeline(field: str, update_dict: dict, insert_dict: dict, cond_dict: dict):
    return [{'$set': {
        field: {
            '$reduce': {
                'input': {'$ifNull': [f"${field}", []]},
                'initialValue': {'help': [], 'update': False},
                'in': {
                    '$cond': [cond_dict,
                              {
                                  'help': {
                                      '$concatArrays': [
                                          "$$value.help",
                                          [update_dict],
                                      ]
                                  },
                                  'update': True
                              },
                              {
                                  'help': {
                                      '$concatArrays': ["$$value.help", ["$$this"]]
                                  },
                                  'update': "$$value.update"
                              }
                              ]
                }
            }
        }
    }
    }, {
        '$set': {
            field: {
                '$cond': [{'$eq': [f"${field}.update", False]},
                          {'$concatArrays': [f"${field}.help",
                                             [insert_dict]]},
                          {'$concatArrays': [f"${field}.help", []]}
                          ]
            }}
    }

]
