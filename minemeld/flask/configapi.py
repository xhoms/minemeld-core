#  Copyright 2015-present Palo Alto Networks, Inc
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

# API to work with MineMeld config
#
# Candidate config is edited in Redis:
# - candidate config is represented by an hash with key name REDIS_KEY_CONFIG
# - the hash as the following fields:
#   - version is the current version of the config
#   - for each node there is a node:<node id> field
#   - pipelines is the field with the pipelines descriptions
#
# Version has a format <uuid>+<number>
# Every time the config is modified the version the number part of the version
# is incremented.
# The API to modify the config should provide a version, if the version
# is different from the current version number the change is discarded
# If the change is applied, the version is incremented and the new version
# is returned.
# The changes should be applied this way:
# - request version is compared with config version, if different -> error
# - candidate config is locked
# - candidate config is copied to temp config key
# - changes are applied
# - if error -> drop
# - version incremented
# - old candidate deleted
# - new config renamed to original key
# - new version is returned

import yaml
import uuid
import time
import json
import copy

import minemeld.run.config

import redis
from blinker import signal
from flask import request, jsonify

from .redisclient import SR
from .aaa import MMBlueprint
from .logger import LOG
from . import utils


__all__ = ['BLUEPRINT']


FEED_INTERVAL = 100

# these should be in sync with restore.py
REDIS_KEY_PREFIX = 'mm:config:'
REDIS_KEY_CONFIG = REDIS_KEY_PREFIX+'candidate'

REDIS_NODES_LIST = 'nodes'
LOCK_TIMEOUT = 3000


BLUEPRINT = MMBlueprint('config', __name__, url_prefix='/config')

REDIS_COPY_LUA_SCRIPT = """
local s = KEYS[1]
local d = KEYS[2]

redis.call("RESTORE", d, 0, redis.call("DUMP", s))
return "OK"
"""

REDIS_COPY_SCRIPT = None


class VersionMismatchError(Exception):
    pass


class MMConfigVersion(object):
    def __init__(self, version=None):
        if version is None:
            self.config = str(uuid.uuid4())
            self.counter = 0
            return

        LOG.debug('version: %s', version)

        self.config, self.counter = version.split('+', 1)
        self.counter = int(self.counter)

    def __str__(self):
        return '%s+%d' % (self.config, self.counter)

    def __repr__(self):
        return 'MMConfigVersion(%s+%d)' % (self.config, self.counter)

    def __eq__(self, other):
        return self.config == other.config and self.counter == other.counter

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iadd__(self, y):
        self.counter += y
        return self


def _signal_change():
    signal('mm-status').send(
        '<candidate-config>',
        data={
            'status': SR.hget(REDIS_KEY_CONFIG, 'version'),
            'timestamp': int(time.time()*1000)
        }
    )


def _lock(resource):
    resname = resource+':lock'
    value = str(uuid.uuid4())
    result = SR.set(resname, value,
                    nx=True, px=LOCK_TIMEOUT)

    if result is None:
        return None

    return value


def _lock_timeout(resource, timeout=30):
    t1 = time.time()
    tt = t1+timeout

    while t1 < tt:
        result = _lock(resource)
        if result is not None:
            return result

        t1 = time.sleep(0.01)

    return None


def _unlock(resource, value):
    resname = resource+':lock'
    result = SR.get(resname)

    if result == value:
        SR.delete(resname)
        return True

    LOG.error('lost lock %s - %s', value, result)

    return False


def _redlock(f):
    def _redlocked(*args, **kwargs):
        lock = kwargs.pop('lock', False)
        timeout = kwargs.pop('timeout', 30)

        if lock:
            clock = _lock_timeout(REDIS_KEY_CONFIG, timeout=timeout)
            if clock is None:
                raise ValueError('Unable to lock config')
            LOG.info('lock set %s', clock)

        result = f(*args, **kwargs)

        if lock:
            _unlock(REDIS_KEY_CONFIG, clock)
            LOG.info('lock cleared %s', clock)

        return result

    return _redlocked


def _nodes_ids():
    for k in SR.hkeys(REDIS_KEY_CONFIG):
        if not k.startswith('node:'):
            continue

        yield k


def _set_stanza(stanza, value, config_key=REDIS_KEY_CONFIG):
    SR.hset(config_key, stanza, json.dumps(value))


@_redlock
def _get_stanza(stanza, config_key=REDIS_KEY_CONFIG):
    value = SR.hget(config_key, stanza)
    if value is None:
        return None

    value = json.loads(value)

    return value


def _load_running_config():
    return _load_config_from_file(utils.running_config_path())


def _load_committed_config():
    return _load_config_from_file(utils.committed_config_path())


def _load_config_from_file(rcpath):
    with open(rcpath, 'r') as f:
        rcconfig = yaml.safe_load(f)

    if rcconfig is None:
        rcconfig = {}

    version = MMConfigVersion()
    tempconfigkey = REDIS_KEY_PREFIX+str(version)

    SR.hset(tempconfigkey, 'version', str(version))

    if 'fabric' in rcconfig:
        _set_stanza(
            'fabric',
            {'name': 'fabric', 'properties': rcconfig['fabric']},
            config_key=tempconfigkey
        )

    if 'mgmtbus' in rcconfig:
        _set_stanza(
            'mgmtbus',
            {'name': 'mgmtbus', 'properties': rcconfig['mgmtbus']},
            config_key=tempconfigkey
        )

    nodes = rcconfig.get('nodes', {})
    for idx, (node_id, nodevalue) in enumerate(nodes.iteritems()):
        _set_stanza(
            'node:{}'.format(node_id),
            {'main': nodevalue},
            config_key=tempconfigkey
        )

    pipelines = utils.pipelines()
    _set_stanza(
        'pipelines',
        pipelines,
        config_key=tempconfigkey
    )

    clock = _lock_timeout(REDIS_KEY_CONFIG)
    if clock is None:
        SR.delete(tempconfigkey)
        raise ValueError('Unable to lock config')

    SR.delete(REDIS_KEY_CONFIG)
    SR.rename(tempconfigkey, REDIS_KEY_CONFIG)

    _unlock(REDIS_KEY_CONFIG, clock)

    _signal_change()

    return str(version)


def _commit_config(version):
    ccpath = utils.committed_config_path()

    clock = _lock_timeout(REDIS_KEY_CONFIG)
    if clock is None:
        raise ValueError('Unable to lock config')

    config_info = _config_info()

    if version != config_info['version']:
        raise VersionMismatchError('Versions mismatch')

    newconfig = {}

    fabric = _get_stanza('fabric')
    if fabric is not None:
        newconfig['fabric'] = json.loads(fabric)['properties']

    mgmtbus = _get_stanza('mgmtbus')
    if mgmtbus is not None:
        newconfig['mgmtbus'] = json.loads(mgmtbus)['properties']

    newconfig['nodes'] = {}
    for node_key in _nodes_ids():
        node_id = node_key.split(':', 1)[1]

        node = _get_stanza('node:{}'.format(node_id))
        if node is None:
            continue

        if node['id'] in newconfig:
            raise ValueError('Error in config: duplicate node id - %s' %
                             node['id'])
        if 'properties' not in node:
            raise ValueError('Error in config: no properties for node %s' %
                             node['id'])
        newconfig['nodes'][node['id']] = node['properties']

    pipelines = _get_stanza('pipelines')
    if pipelines is None:
        pipelines = {
            'pipelines': [],
            'nodes': []
        }
    pipelines.pop('version', None)

    _unlock(REDIS_KEY_CONFIG, clock)

    # we build a copy of the config for validation
    # original config is not used because it could be modified
    # during validation
    temp_config = minemeld.run.config.MineMeldConfig.from_dict(copy.deepcopy(newconfig))
    valid = minemeld.run.config.resolve_prototypes(temp_config)
    if not valid:
        raise ValueError('Error resolving prototypes')
    messages = minemeld.run.config.validate_config(temp_config)
    if len(messages) != 0:
        return messages

    with open(ccpath, 'w') as f:
        yaml.safe_dump(
            newconfig,
            f,
            encoding='utf-8',
            default_flow_style=False
        )

    with open(utils.pipelines_path(), 'w') as f:
        yaml.safe_dump(
            pipelines,
            f,
            encoding='utf-8',
            default_flow_style=False
        )

    SR.hset(REDIS_KEY_CONFIG, 'changed', 0)

    return 'OK'


def _increment_config_version():
    version = SR.hget(REDIS_KEY_CONFIG, 'version')
    if version is None:
        raise ValueError('candidate config not initialized')

    version = MMConfigVersion(version=version)
    version += 1

    return version


@_redlock
def _config_full():
    cinfo = _config_info(lock=False)

    cinfo['nodes'] = []
    for node_key in _nodes_ids():
        node_id = node_key.split(':', 1)[1]
        nc = _get_stanza('node:{}'.format(node_id), lock=False)
        nc['id'] = node_id
        cinfo['nodes'].append(nc)

    cinfo['pipelines'] = _get_stanza('pipelines', lock=False)

    return cinfo


@_redlock
def _config_info():
    version = SR.hget(REDIS_KEY_CONFIG, 'version')
    if version is None:
        raise ValueError('candidate config not initialized')

    # check config version format
    # raises exception if not valid
    MMConfigVersion(version=version)

    fabric = SR.hget(REDIS_KEY_CONFIG, 'fabric') is not None
    mgmtbus = SR.hget(REDIS_KEY_CONFIG, 'mgmtbus') is not None
    pipelines = SR.hget(REDIS_KEY_CONFIG, 'pipelines') is not None
    changed = SR.hget(REDIS_KEY_CONFIG, 'changed') == "1"

    return {
        'fabric': fabric,
        'mgmtbus': mgmtbus,
        'pipelines': pipelines,
        'version': version,
        'changed': changed
    }


def _create_node(parameters, rkey):
    _id = parameters.get('id', None)
    if _id is None:
        raise RuntimeError('id parameter required in createNode action')

    value = {
        'main': parameters.get('main', {})
    }
    side_config = parameters.get('side_config', None)
    if side_config is not None:
        value['side_config'] = side_config

    stanza_id = 'node:{}'.format(_id)

    for eid in _nodes_ids():
        if eid == stanza_id:
            raise RuntimeError('Node {} already exists'.format(_id))

    _set_stanza(stanza_id, value, rkey)


def _delete_node(parameters, rkey):
    _id = parameters.get('id', None)
    if _id is None:
        raise RuntimeError('id parameter required in deleteNode action')

    stanza_id = 'node:{}'.format(_id)

    for eid in _nodes_ids():
        if eid == stanza_id:
            SR.hdel(rkey, eid)
            return

    raise RuntimeError('Unknown node {}'.format(_id))


def _update_node(parameters, rkey):
    _id = parameters.get('id', None)
    if _id is None:
        raise RuntimeError('id parameter required in updateNode action')

    stanza_id = 'node:{}'.format(_id)

    value = {
        'main': parameters.get('main', {})
    }
    side_config = parameters.get('side_config', None)
    if side_config is not None:
        value['side_config'] = side_config

    for eid in _nodes_ids():
        if eid == stanza_id:
            _set_stanza(stanza_id, value, rkey)
            return

    raise RuntimeError('Unknown node {}'.format(_id))


def _create_pipeline_node(parameters, rkey):
    _id = parameters.get('id', None)
    if _id is None:
        raise RuntimeError('id parameter required in createPipelineNode action')

    value = {
        'id': _id,
        'name': parameters.get('name', ':{}:'.format(_id))
    }
    comment = parameters.get('comment', None)
    if comment is not None:
        value['comment'] = comment
    pipeline = parameters.get('pipeline', None)
    if pipeline is not None:
        value['pipeline'] = pipeline

    pipelines = _get_stanza('pipelines', rkey)

    nodes = [n for n in pipelines['nodes'] if n['id'] == _id]
    if len(nodes) != 0:
        raise RuntimeError('Pipeline Node ID {} already exists'.format(_id))

    pipelines['nodes'].append(value)

    _set_stanza('pipelines', pipelines, rkey)


def _delete_pipeline_node(parameters, rkey):
    _id = parameters.get('id', None)
    if _id is None:
        raise RuntimeError('id parameter required in createPipelineNode action')

    pipelines = _get_stanza('pipelines', rkey)

    nodes = [n for n in pipelines['nodes'] if n['id'] != _id]
    if len(nodes) == len(pipelines['nodes']):
        raise RuntimeError('Unknown pipeline node ID {}'.format(_id))

    pipelines['nodes'] = nodes

    _set_stanza('pipelines', pipelines, rkey)


def _update_pipeline_node(parameters, rkey):
    _id = parameters.get('id', None)
    if _id is None:
        raise RuntimeError('id parameter required in createPipelineNode action')

    value = {
        'id': _id,
        'name': parameters.get('name', ':{}:'.format(_id))
    }
    comment = parameters.get('comment', None)
    if comment is not None:
        value['comment'] = comment
    pipeline = parameters.get('pipeline', None)
    if pipeline is not None:
        value['pipeline'] = pipeline

    pipelines = _get_stanza('pipelines', rkey)

    nodes = [n for n in pipelines['nodes'] if n['id'] != _id]
    if len(nodes) == len(pipelines['nodes']):
        raise RuntimeError('Unknown pipeline node ID {}'.format(_id))

    pipelines['nodes'].append(value)

    _set_stanza('pipelines', pipelines, rkey)


def _create_pipeline(parameters, rkey):
    _id = parameters.get('id', None)
    if _id is None:
        raise RuntimeError('id parameter required in createPipelineNode action')

    value = {
        'id': _id,
        'name': parameters.get('name', ':{}:'.format(_id))
    }
    comment = parameters.get('comment', None)
    if comment is not None:
        value['comment'] = comment

    pipelines = _get_stanza('pipelines', rkey)

    plines = [n for n in pipelines['pipelines'] if n['id'] == _id]
    if len(plines) != 0:
        raise RuntimeError('Pipeline ID {} already exists'.format(_id))

    pipelines['pipelines'].append(value)

    _set_stanza('pipelines', pipelines, rkey)


def _delete_pipeline(parameters, rkey):
    _id = parameters.get('id', None)
    if _id is None:
        raise RuntimeError('id parameter required in createPipelineNode action')

    pipelines = _get_stanza('pipelines', rkey)

    plines = [n for n in pipelines['pipelines'] if n['id'] != _id]
    if len(plines) == len(pipelines['pipelines']):
        raise RuntimeError('Pipeline node ID {}'.format(_id))

    pipelines['pipelines'] = plines

    _set_stanza('pipelines', pipelines, rkey)


def _update_pipeline(parameters, rkey):
    _id = parameters.get('id', None)
    if _id is None:
        raise RuntimeError('id parameter required in createPipelineNode action')

    value = {
        'id': _id,
        'name': parameters.get('name', ':{}:'.format(_id))
    }
    comment = parameters.get('comment', None)
    if comment is not None:
        value['comment'] = comment

    pipelines = _get_stanza('pipelines', rkey)

    plines = [n for n in pipelines['pipelines'] if n['id'] != _id]
    if len(plines) == len(pipelines['pipelines']):
        raise RuntimeError('Pipeline node ID {}'.format(_id))

    pipelines['pipelines'].append(value)

    _set_stanza('pipelines', pipelines, rkey)


@_redlock
def _apply_changes(version, changes):
    cversion = SR.hget(REDIS_KEY_CONFIG, 'version')
    if cversion != version:
        raise VersionMismatchError()

    next_version = _increment_config_version()

    tempconfigkey = REDIS_KEY_PREFIX+str(next_version)

    REDIS_COPY_SCRIPT(keys=[REDIS_KEY_CONFIG, tempconfigkey])

    for change in changes:
        action = change.pop('action', None)
        if action is None:
            raise RuntimeError('Invalid change {!r}'.format(change))

        parameters = change.pop('parameters', {})
        if action == 'createNode':
            _create_node(parameters, tempconfigkey)
        elif action == 'deleteNode':
            _delete_node(parameters, tempconfigkey)
        elif action == 'updateNode':
            _update_node(parameters, tempconfigkey)
        elif action == 'createPipelineNode':
            _create_pipeline_node(parameters, tempconfigkey)
        elif action == 'deletePipelineNode':
            _delete_pipeline_node(parameters, tempconfigkey)
        elif action == 'updatePipelineNode':
            _update_pipeline_node(parameters, tempconfigkey)
        elif action == 'createPipeline':
            _create_pipeline(parameters, tempconfigkey)
        elif action == 'deletePipeline':
            _delete_pipeline(parameters, tempconfigkey)
        elif action == 'updatePipeline':
            _update_pipeline(parameters, tempconfigkey)
        else:
            raise RuntimeError('Unknown action: {!r}'.format(action))

    SR.hset(tempconfigkey, 'version', str(next_version))
    SR.rename(tempconfigkey, REDIS_KEY_CONFIG)

    _signal_change()

    return str(next_version)


@BLUEPRINT.route('/running', methods=['GET'], read_write=False)
def get_running_config():
    result = utils.running_config()
    result['pipelines'] = utils.pipelines()

    return jsonify(result=result)


@BLUEPRINT.route('/committed', methods=['GET'], read_write=False)
def get_committed_config():
    result = utils.committed_config()
    result['pipelines'] = utils.pipelines()

    return jsonify(result=result)


# API for manipulating candidate config
@BLUEPRINT.route('/reload', methods=['GET'], read_write=False)
def reload_running_config():
    cname = request.args.get('c', 'running')

    try:
        if cname == 'running':
            version = _load_running_config()
        elif cname == 'committed':
            version = _load_committed_config()
        else:
            return jsonify(error={'message': 'Unknown config'}), 400

    except Exception as e:
        LOG.exception('Error in loading config')
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=str(version))


@BLUEPRINT.route('/commit', methods=['POST'], read_write=True)
def commit():
    try:
        body = request.get_json()
    except Exception as e:
        return jsonify(error={'message': str(e)}), 400

    version = body.get('version', None)
    if body is None:
        return jsonify(error={'message': 'version required'}), 400

    try:
        result = _commit_config(version)
    except VersionMismatchError:
        return jsonify(error={'message': 'version mismatch'}), 409
    except Exception as e:
        LOG.exception('exception in commit')
        return jsonify(error={'message': str(e)}), 400

    if result != 'OK':
        return jsonify(error={'message': result}), 402

    return jsonify(result='OK')


@BLUEPRINT.route('/info', methods=['GET'], read_write=False)
def get_config_info():
    try:
        result = _config_info(lock=True)
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=result)


@BLUEPRINT.route('/full', methods=['GET'], read_write=False)
def get_config_full():
    try:
        result = _config_full(lock=True)

    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=result)


@BLUEPRINT.route('/apply', methods=['POST'], read_write=False)
def apply_changes():
    try:
        body = request.get_json()
    except Exception as e:
        return jsonify(error={'message': str(e)}), 400

    # check version
    version = body.get('version', None)
    if version is None:
        return jsonify(error={'message': 'missing version field'}), 400

    try:
        result = _apply_changes(version, body.get('changes', []))
    except VersionMismatchError:
        return jsonify(error={'message': 'Version mismatch'}), 409
    except Exception as e:
        LOG.exception('exception in applying changes')
        return jsonify(error={'message': str(e)}), 400

    return jsonify(result=result)


@_redlock
def _init_config():
    try:
        _config_info(lock=False)

    except ValueError:
        LOG.info('Loading running config in memory')

        try:
            _load_running_config()

        except OSError:
            LOG.exception('Error loading running config')


def init_app(app, redis_url):
    global REDIS_COPY_SCRIPT

    app.before_first_request(_init_config)

    # init lua scripts
    initSR = redis.StrictRedis.from_url(redis_url)
    REDIS_COPY_SCRIPT = initSR.register_script(REDIS_COPY_LUA_SCRIPT)
