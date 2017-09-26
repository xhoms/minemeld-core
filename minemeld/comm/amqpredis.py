#  Copyright 2015-2016 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""
This module implements AMQP communication class for mgmtbus and fabric.
"""

from __future__ import absolute_import

import amqp.connection
import amqp
import gevent
import gevent.event
import ujson as json
import logging
import uuid

import redis

LOG = logging.getLogger(__name__)


class RedisPubChannel(object):
    def __init__(self, topic, connection_pool):
        self.topic = topic
        self.prefix = 'mm:topic:{}'.format(self.topic)

        self.connection_pool = connection_pool
        self.SR = None

        self.num_publish = 0

    def connect(self):
        if self.SR is not None:
            return

        self.SR = redis.StrictRedis(
            connection_pool=self.connection_pool
        )

        tkeys = self.SR.keys(pattern='{}:*'.format(self.prefix))
        if len(tkeys) > 0:
            LOG.info('Deleting {} old keys for {}'.format(len(tkeys), self.prefix))
            self.SR.delete(*tkeys)

    def disconnect(self):
        if self.SR is None:
            return

        self.SR = None

    def lagger(self):
        # get status of subscribers
        subscribersc = self.SR.lrange(
            '{}:subscribers'.format(self.prefix),
            0, -1
        )
        subscribersc = [int(sc) for sc in subscribersc]

        # check the lagger
        minsubc = 0
        if len(subscribersc) != 0:
            minsubc = min(subscribersc)

        return minsubc

    def gc(self, lagger):
        minhighbits = lagger >> 12

        minqname = '{}:queue:{:013X}'.format(
            self.prefix,
            minhighbits
        )

        # delete all the lists before the lagger
        queues = self.SR.keys('{}:queue:*'.format(self.prefix))
        LOG.debug('topic {} - queues: {!r}'.format(self.topic, queues))
        queues = [q for q in queues if q < minqname]
        LOG.debug('topic {} - queues to be deleted: {!r}'.format(self.topic, queues))
        if len(queues) != 0:
            LOG.debug('topic {} - deleting {!r}'.format(
                self.topic,
                queues
            ))
            self.SR.delete(*queues)

    def publish(self, method, params=None):
        high_bits = self.num_publish >> 12
        low_bits = self.num_publish & 0xfff

        if (low_bits % 128) == 127:
            lagger = self.lagger()
            LOG.debug('topic {} - sent {} lagger {}'.format(
                self.topic,
                self.num_publish,
                lagger
            ))

            while (self.num_publish - lagger) > 1024:
                LOG.debug('topic {} - waiting lagger delta: {}'.format(
                    self.topic,
                    self.num_publish - lagger
                ))
                gevent.sleep(0.1)
                lagger = self.lagger()

            if low_bits == 0xfff:
                # we are switching to a new list, gc
                self.gc(lagger)

        msg = {
            'method': method,
            'params': params
        }

        qname = '{}:queue:{:013X}'.format(
            self.prefix,
            high_bits
        )

        self.SR.rpush(qname, json.dumps(msg))
        self.num_publish += 1


class AMQPRpcFanoutClientChannel(object):
    def __init__(self, fanout):
        self.fanout = fanout
        self.active_rpcs = {}

        self._in_channel = None
        self._out_channel = None
        self._in_queue = None

    def _in_callback(self, msg):
        try:
            msg = json.loads(msg.body)
        except ValueError:
            LOG.error("Invalid JSON in msg body")
            return

        LOG.debug('AMQPRpcFanoutClientChannel - received result %s', msg)

        id_ = msg.get('id', None)
        if id_ is None:
            LOG.error("No id field in RPC reply")
            return
        if id_ not in self.active_rpcs:
            LOG.error("Unknown id received in RPC reply: %s", id_)
            return

        source = msg.get('source', None)
        if source is None:
            LOG.error('No source field in RPC reply')
            return

        actreq = self.active_rpcs[id_]

        result = msg.get('result', None)
        if result is None:
            actreq['errors'] += 1
            errmsg = msg.get('error', 'no error in reply')
            LOG.error('Error in RPC reply from %s: %s', source, errmsg)
        else:
            actreq['answers'][source] = result

        if len(actreq['answers'])+actreq['errors'] >= actreq['num_results']:
            actreq['event'].set({
                'answers': actreq['answers'],
                'errors': actreq['errors']
            })
            self.active_rpcs.pop(id_)

        gevent.sleep(0)

    def send_rpc(self, method, params=None, num_results=0, and_discard=False):
        if self._in_channel is None:
            raise RuntimeError('Not connected')

        if params is None:
            params = {}

        id_ = str(uuid.uuid1())

        body = {
            'reply_to': self._in_queue.queue,
            'method': method,
            'id': id_,
            'params': params
        }

        LOG.debug('AMQPRpcFanoutClientChannel - sending %s to %s',
                  body, self.fanout)

        msg = amqp.Message(
            body=json.dumps(body),
            reply_to=self._in_queue.queue,
            exchange=self.fanout
        )

        event = gevent.event.AsyncResult()

        if num_results == 0:
            event.set({
                'answers': {},
                'errors': 0
            })
            return event

        self.active_rpcs[id_] = {
            'cmd': method,
            'answers': {},
            'num_results': num_results,
            'event': event,
            'errors': 0,
            'discard': and_discard
        }

        self._out_channel.basic_publish(msg, exchange=self.fanout)

        gevent.sleep(0)

        return event

    def connect(self, conn):
        if self._in_channel is not None:
            return

        self._in_channel = conn.channel()
        self._in_queue = self._in_channel.queue_declare(exclusive=True)
        self._in_channel.basic_consume(
            callback=self._in_callback,
            no_ack=True,
            exclusive=True
        )

        self._out_channel = conn.channel()
        self._out_channel.exchange_declare(
            self.fanout,
            'fanout',
            auto_delete=True
        )

    def disconnect(self):
        if self._in_channel is None:
            return

        self._in_channel.close()
        self._out_channel.close()


class AMQPRpcServerChannel(object):
    def __init__(self, name, obj, allowed_methods=None,
                 method_prefix='', fanout=None):
        if allowed_methods is None:
            allowed_methods = []

        self.name = name
        self.obj = obj
        self.channel = None
        self.allowed_methods = allowed_methods
        self.fanout = fanout
        self.method_prefix = method_prefix

    def _send_result(self, replyq, id_, result=None, error=None):
        ans = {
            'source': self.name,
            'id': id_,
            'result': result,
            'error': error
        }
        ans = json.dumps(ans)
        msg = amqp.Message(body=ans)
        self.channel.basic_publish(msg, routing_key=replyq)

        LOG.debug('AMQPRpcServerChannel - sent result %s', ans)

        gevent.sleep(0)

    def _callback(self, msg):
        try:
            body = json.loads(msg.body)
        except ValueError:
            LOG.error("Invalid JSON in msg body")
            return
        LOG.debug('in callback - %s', body)

        reply_to = body.get('reply_to', None)
        if reply_to is None:
            LOG.error('No reply_to in RPC request')
            return

        method = body.get('method', None)
        id_ = body.get('id', None)
        params = body.get('params', {})

        if method is None:
            LOG.error('No method in msg body')
            return
        if id_ is None:
            LOG.error('No id in msg body')
            return

        method = self.method_prefix+method

        if method not in self.allowed_methods:
            LOG.error("method not allowed: %s", method)
            self._send_result(reply_to, id_, error="Method not allowed")

        m = getattr(self.obj, method, None)
        if m is None:
            LOG.error("Method %s not defined for %s", method, self.name)
            self._send_result(reply_to, id_, error="Method not defined")

        try:
            result = m(**params)

        except gevent.GreenletExit:
            raise

        except Exception as e:
            self._send_result(reply_to, id_, error=str(e))

        else:
            self._send_result(reply_to, id_, result=result)

    def connect(self, conn):
        if self.channel is not None:
            return

        self.channel = conn.channel()

        LOG.debug('opening queue %s', self.name+':rpc')

        q = self.channel.queue_declare(
            queue=self.name+':rpc',
            exclusive=False
        )

        if self.fanout:
            LOG.debug("Binding queue to fanout %s", self.fanout)
            self.channel.exchange_declare(
                self.fanout,
                'fanout',
                auto_delete=True
            )
            self.channel.queue_bind(
                queue=q.queue,
                exchange=self.fanout
            )

        self.channel.basic_consume(
            callback=self._callback,
            no_ack=True,
            exclusive=True
        )

    def disconnect(self):
        if self.channel is None:
            return

        self.channel.close()
        self.channel = None


class RedisSubChannel(object):
    def __init__(self, topic, connection_pool, object_,
                allowed_methods, name=None):
        self.topic = topic
        self.prefix = 'mm:topic:{}'.format(self.topic)
        self.channel = None
        self.name = name
        self.object = object_
        self.allowed_methods = allowed_methods

        self.num_callbacks = 0

    def _callback(self, msg):
        try:
            msg = json.loads(msg)
        except ValueError:
            LOG.error("invalid message received")
            return

        method = msg.get('method', None)
        params = msg.get('params', {})
        if method is None:
            LOG.error("Message without method field")
            return

        if method not in self.allowed_methods:
            LOG.error("Method not allowed: %s", method)
            return

        m = getattr(self.object, method, None)
        if m is None:
            LOG.error('Method %s not defined', method)
            return

        try:
            m(**params)

        except gevent.GreenletExit:
            raise

        except:
            LOG.exception('Exception in handling %s on topic %s '
                          'with params %s', method, self.topic, params)

        self.num_callbacks += 1

    def connect(self):
        pass

    def disconnect(self):
        pass

class AMQPRedis(object):
    def __init__(self, config):
        self.num_connections = config.pop('num_connections', 1)
        self.priority = config.pop('priority', 0)

        if 'host' not in config:
            config['host'] = '127.0.0.1'

        self.amqp_config = config

        self.rpc_server_channels = {}
        self.pub_channels = []
        self.sub_channels = []
        self.rpc_fanout_clients_channels = []

        self.rpc_out_channel = None
        self.rpc_out_queue = None
        self.active_rpcs = {}

        self._rpc_in_connection = None

        self._connections = []
        self.ioloops = []

        self.failure_listeners = []

        # XXX
        self.redis_config = {
            'url': 'unix:///var/run/redis.sock?db=0'
        }
        self.redis_cp = redis.ConnectionPool.from_url(
            self.redis_config['url']
        )

    def add_failure_listener(self, listener):
        self.failure_listeners.append(listener)

    def request_rpc_server_channel(self, name, obj=None, allowed_methods=None,
                                   method_prefix='', fanout=None):
        if allowed_methods is None:
            allowed_methods = []

        if name in self.rpc_server_channels:
            return

        self.rpc_server_channels[name] = AMQPRpcServerChannel(
            name,
            obj,
            method_prefix=method_prefix,
            allowed_methods=allowed_methods,
            fanout=fanout
        )

    def request_rpc_fanout_client_channel(self, topic):
        c = AMQPRpcFanoutClientChannel(topic)
        self.rpc_fanout_clients_channels.append(c)
        return c

    def request_pub_channel(self, topic):
        redis_pub_channel = RedisPubChannel(
            topic=topic,
            connection_pool=self.redis_cp
        )
        self.pub_channels.append(redis_pub_channel)

        return redis_pub_channel

    def request_sub_channel(self, topic, obj=None, allowed_methods=None,
                            name=None, max_length=None):
        if allowed_methods is None:
            allowed_methods = []

        subchannel = RedisSubChannel(
            topic=topic,
            connection_pool=self.redis_cp,
            object_=obj,
            allowed_methods=allowed_methods,
            name=name
        )
        self.sub_channels.append(subchannel)

    def _rpc_callback(self, msg):
        try:
            msg = json.loads(msg.body)
        except ValueError:
            LOG.error("Invalid JSON in msg body")
            return
        id_ = msg.get('id', None)
        if id_ is None:
            LOG.error("No id field in RPC reply")
            return
        if id_ not in self.active_rpcs:
            LOG.error("Unknown id received in RPC reply: %s", id_)
            return
        ar = self.active_rpcs.pop(id_)
        ar.set({
            'error': msg.get('error', None),
            'result': msg.get('result', None)
        })

    def send_rpc(self, dest, method, params,
                 block=True, timeout=None):
        if len(self._connections) == 0:
            raise RuntimeError('Not connected')

        id_ = str(uuid.uuid1())

        body = {
            'reply_to': self.rpc_out_queue.queue,
            'method': method,
            'id': id_,
            'params': params
        }
        LOG.debug('sending %s to %s', body, dest+':rpc')
        msg = amqp.Message(
            body=json.dumps(body),
            reply_to=self.rpc_out_queue.queue
        )

        self.active_rpcs[id_] = gevent.event.AsyncResult()
        self.rpc_out_channel.basic_publish(msg, routing_key=dest+':rpc')

        try:
            result = self.active_rpcs[id_].get(block=block, timeout=timeout)

        except gevent.timeout.Timeout:
            self.active_rpcs.pop(id_)
            raise

        return result

    def _ioloop(self, j):
        LOG.debug('start draining events on connection %r', j)

        conn = self._rpc_in_connection
        if j is not None:
            conn = self._connections[j]

        while True:
            conn.drain_events()

    def _sub_ioloop(self, schannel):
        LOG.debug('start draining messages on topic {}'.format(schannel.topic))

        counter = 0
        SR = redis.StrictRedis(connection_pool=self.redis_cp)
        subscribers_key = '{}:subscribers'.format(schannel.prefix)
        sub_number = None

        while True:
            base = counter & 0xfff
            top = min(base + 127, 0xfff)

            msgs = SR.lrange(
                '{}:queue:{:013X}'.format(schannel.prefix, counter >> 12),
                base,
                top
            )

            for m in msgs:
                LOG.debug('topic {} - {!r}'.format(
                    schannel.topic,
                    m
                ))
                schannel._callback(m)

            LOG.debug('topic {} - base {} top {} counter {} read {}'.format(
                schannel.topic,
                base,
                top,
                counter,
                len(msgs)
            ))

            counter += len(msgs)

            if len(msgs) > 0:
                if sub_number is None:
                    sub_number = SR.rpush(
                        subscribers_key,
                        len(msgs)
                    )
                    sub_number -= 1

                else:
                    SR.lset(
                        subscribers_key,
                        sub_number,
                        counter
                    )

            if len(msgs) < (top - base + 1):
                gevent.sleep(1.0)
            else:
                gevent.sleep(0)

    def _ioloop_failure(self, g):
        LOG.debug('_ioloop_failure')

        try:
            g.get()

        except gevent.GreenletExit:
            return

        except:
            LOG.exception("_ioloop_failure: exception in ioloop")
            for l in self.failure_listeners:
                l()

    def _blocked(self, reason):
        LOG.error('Connection blocked: {}'.format(reason))

    def _unblocked(self):
        LOG.info('Connection unblocked')

    def start(self, start_dispatching=True):
        num_conns_total = sum([
            len(self.rpc_fanout_clients_channels),
            1
        ])

        for j in xrange(num_conns_total):
            self.amqp_config['on_blocked'] = self._blocked
            self.amqp_config['on_unblocked'] = self._unblocked
            c = amqp.connection.Connection(**self.amqp_config)
            c.sock._read_event.priority = self.priority
            c.sock._write_event.priority = self.priority
            self._connections.append(c)

        csel = 0
        for rfc in self.rpc_fanout_clients_channels:
            rfc.connect(self._connections[csel])
            csel += 1

        # create rpc out channel
        self.rpc_out_channel = \
            self._connections[-1].channel()
        self.rpc_out_queue = self.rpc_out_channel.queue_declare(
            exclusive=False
        )
        self.rpc_out_channel.basic_consume(
            callback=self._rpc_callback,
            no_ack=True,
            exclusive=True
        )

        self.amqp_config['on_blocked'] = self._blocked
        self.amqp_config['on_unblocked'] = self._unblocked
        self._rpc_in_connection = amqp.connection.Connection(
            **self.amqp_config
        )
        self._rpc_in_connection.sock._read_event.priority = self.priority
        self._rpc_in_connection.sock._write_event.priority = self.priority

        for rpcc in self.rpc_server_channels.values():
            rpcc.connect(self._rpc_in_connection)

        for sc in self.sub_channels:
            sc.connect()

        for pc in self.pub_channels:
            pc.connect()

        if start_dispatching:
            self.start_dispatching()

    def start_dispatching(self):
        # spin up greenlets for each connection
        for j in xrange(len(self._connections)):
            g = gevent.spawn(self._ioloop, j)
            self.ioloops.append(g)
            g.link_exception(self._ioloop_failure)

        # spin up greenlet for _rpc_in_connection
        g = gevent.spawn(self._ioloop, None)
        self.ioloops.append(g)
        g.link_exception(self._ioloop_failure)

        for schannel in self.sub_channels:
            g = gevent.spawn(self._sub_ioloop, schannel)
            self.ioloops.append(g)
            g.link_exception(self._ioloop_failure)

    def stop(self):
        # kill ioloops
        for j in xrange(len(self.ioloops)):
            self.ioloops[j].unlink(self._ioloop_failure)
            self.ioloops[j].kill()
            self.ioloops[j] = None
        self.ioloops = None

        # close channels
        for rpcc in self.rpc_server_channels.values():
            try:
                rpcc.disconnect()
            except amqp.AMQPError:
                LOG.debug("exception in disconnect: ", exc_info=True)

        for pc in self.pub_channels:
            try:
                pc.disconnect()
            except Exception:
                LOG.debug("exception in disconnect: ", exc_info=True)

        for sc in self.sub_channels:
            try:
                sc.disconnect()
            except Exception:
                LOG.debug("exception in disconnect: ", exc_info=True)

        for rfc in self.rpc_fanout_clients_channels:
            try:
                rfc.disconnect()
            except amqp.AMQPError:
                LOG.debug("exception in disconnect: ", exc_info=True)

        self.rpc_out_channel.close()

        # close connections
        for j in xrange(len(self._connections)):
            self._connections[j].close()
            self._connections[j] = None

        self._rpc_in_connection.close()
        self._rpc_in_connection = None
