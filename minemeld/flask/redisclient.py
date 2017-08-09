import os

import redis
import werkzeug.local

from flask import g

from .logger import LOG


__all__ = ['init_app', 'SR']


REDIS_CP = None


def get_SR():
    SR = getattr(g, '_redis_client', None)
    if SR is None:
        SR = redis.StrictRedis(connection_pool=REDIS_CP)
        g._redis_client = SR
    return SR


def teardown(exception):
    SR = getattr(g, '_redis_client', None)
    if SR is not None:
        g._redis_client = None
        LOG.debug(
            'redis connection pool: in use: {} available: {}'.format(
                len(REDIS_CP._in_use_connections),
                len(REDIS_CP._available_connections)
            )
        )


SR = werkzeug.local.LocalProxy(get_SR)


def init_app(app, redis_url):
    global REDIS_CP

    REDIS_CP = redis.ConnectionPool.from_url(
        redis_url,
        max_connections=int(os.environ.get('REDIS_MAX_CONNECTIONS', 200))
    )

    app.teardown_appcontext(teardown)
