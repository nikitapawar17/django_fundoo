import redis
redis_obj = redis.StrictRedis(host='localhost', port=6379, db=0)


class RedisService:

    def set_value(self, key, value):  # This method use to set the value in redis cache
        redis_obj.set(key, value)

    def get_value(self, key):  # This method use to get the value from redis cache
        token = redis_obj.get(key)
        return token

    def flush(self):
        redis_obj.flushall()
