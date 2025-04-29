import os
import redis
from dotenv import load_dotenv

load_dotenv()

_redis_client = None


def get_redis_client():
    global _redis_client
    if _redis_client is None:
        redis_host = os.getenv("REDIS_HOST", "redis")
        redis_port = int(os.getenv("REDIS_PORT", 6379))
        _redis_client = redis.Redis(
            host=redis_host, port=redis_port, db=0, decode_responses=True
        )
    return _redis_client
