from katti.DataBaseStuff.MongoengineDocuments.MalwareFamilyMapping import MalwareFamilyMapping
from katti.RedisCacheLayer.RedisMongoCache import RedisMongoCache


def family_mapping_lower(family: str, redis_cache: RedisMongoCache = None):
    family = family.lower()
    if redis_cache:
        cache_hit = redis_cache.get_value(family)
        if cache_hit:
            return cache_hit.decode()
    try:
        new_family = MalwareFamilyMapping.get_family_mapping(family)
    except Exception:
        new_family = family
    if redis_cache:
        redis_cache.insert_value_pair(key=family, value=family.encode(), ttl=2*60)
    return new_family
