import gridfs
from bson import ObjectId
from gridfs import GridOut
from mongoengine import get_db


def gridfs_insert_data(data: bytes, meta_data: dict=None,  db_name: str = 'Katti') -> ObjectId:
    if meta_data is None:
        meta_data = {}
    return gridfs.GridFS(get_db(db_name)).put(data, **meta_data)


def gridfs_get_data(object_id: ObjectId, db_name: str = 'Katti') -> GridOut:
    return gridfs.GridFS(get_db(db_name)).get(object_id)


def grid_fs_delete_data(object_id: ObjectId, db_name: str = 'Katti'):
    gridfs.GridFS(get_db(db_name)).delete(object_id)
