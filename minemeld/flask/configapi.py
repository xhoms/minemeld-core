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

import yaml
import uuid
import time
import json
import copy

import minemeld.run.config

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

        if k.endswith(':version'):
            continue

        yield k


def _set_stanza(stanza, value, version, config_key=REDIS_KEY_CONFIG):
    version_key = stanza+':version'
    cversion = SR.hget(config_key, version_key)
    if cversion is not None:
        if version != MMConfigVersion(version=cversion):
            raise VersionMismatchError('version mismatch, current version %s' %
                                       cversion)
        version += 1

    SR.hset(config_key, version_key, str(version))
    SR.hset(config_key, stanza, json.dumps(value))

    return version


@_redlock
def _get_stanza(stanza, config_key=REDIS_KEY_CONFIG):
    version_key = stanza+':version'

    version = SR.hget(config_key, version_key)
    if version is None:
        return None

    value = SR.hget(config_key, stanza)
    if value is None:
        return None

    value = json.loads(value)
    value['version'] = version

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
    SR.hset(tempconfigkey, 'changed', 0)

    if 'fabric' in rcconfig:
        _set_stanza(
            'fabric',
            {'name': 'fabric', 'properties': rcconfig['fabric']},
            config_key=tempconfigkey,
            version=version
        )

    if 'mgmtbus' in rcconfig:
        _set_stanza(
            'mgmtbus',
            {'name': 'mgmtbus', 'properties': rcconfig['mgmtbus']},
            config_key=tempconfigkey,
            version=version
        )

    nodes = rcconfig.get('nodes', {})
    for idx, (node_id, nodevalue) in enumerate(nodes.iteritems()):
        _set_stanza(
            'node:{}'.format(node_id),
            {'id': node_id, 'properties': nodevalue},
            config_key=tempconfigkey,
            version=version
        )

    pipelines = utils.pipelines()
    _set_stanza(
        'pipelines',
        pipelines,
        config_key=tempconfigkey,
        version=version
    )

    clock = _lock_timeout(REDIS_KEY_CONFIG)
    if clock is None:
        SR.delete(tempconfigkey)
        raise ValueError('Unable to lock config')

    SR.delete(REDIS_KEY_CONFIG)
    SR.rename(tempconfigkey, REDIS_KEY_CONFIG)

    _unlock(REDIS_KEY_CONFIG, clock)

    _signal_change()

    return version.config


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

    SR.hset(REDIS_KEY_CONFIG, 'version', str(version))


@_redlock
def _config_full():
    cinfo = _config_info(lock=False)

    cinfo['nodes'] = []
    for node_key in _nodes_ids():
        node_id = node_key.split(':', 1)[1]
        nc = _get_stanza('node:{}'.format(node_id), lock=False)
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


@_redlock
def _create_node(nodebody):
    info = _config_info()

    version = nodebody.pop('version', None)
    if version != info['version']:
        raise ValueError('version mismatch')
    id_ = nodebody.get('id', None)
    if id_ is None:
        raise ValueError('no ID in node description')

    cversion = MMConfigVersion(version=info['version'])
    cversion.counter = 0

    _set_stanza(
        'node:{}'.format(id_),
        nodebody,
        cversion
    )

    SR.hset(REDIS_KEY_CONFIG, 'changed', 1)

    _increment_config_version()

    _signal_change()

    return {
        'version': str(cversion)
    }


@_redlock
def _delete_node(node_id, version):
    node = _get_stanza('node:{}'.format(node_id))
    if node is None:
        raise ValueError('node {} does not exist'.format(node_id))

    if MMConfigVersion(version=version) != MMConfigVersion(node['version']):
        raise VersionMismatchError('version mismatch')

    SR.hdel(REDIS_KEY_CONFIG, 'node:{}'.format(node_id))
    SR.hdel(REDIS_KEY_CONFIG, 'node:{}:version'.format(node_id))

    SR.hset(REDIS_KEY_CONFIG, 'changed', 1)

    _increment_config_version()

    _signal_change()

    return 'OK'


@_redlock
def _set_stanza_with_lock(stanza, value, version):
    result = _set_stanza(
        stanza,
        value,
        version,
    )

    SR.hset(REDIS_KEY_CONFIG, 'changed', 1)

    _increment_config_version()

    _signal_change()

    return str(result)


def _set_node(node_id, nodebody, lock=False):
    if 'version' not in nodebody:
        raise ValueError('version is required')
    version = MMConfigVersion(version=nodebody.pop('version'))

    return _set_stanza_with_lock(
        'node:{}'.format(node_id),
        nodebody,
        version,
        lock=lock
    )


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


@BLUEPRINT.route('/fabric', methods=['GET'], read_write=False)
def get_fabric():
    try:
        result = _get_stanza('fabric', lock=True)
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    if result is None:
        return jsonify(error={'message': 'Not Found'}), 404

    return jsonify(result=result)


@BLUEPRINT.route('/mgmtbus', methods=['GET'], read_write=False)
def get_mgmtbus():
    try:
        result = _get_stanza('mgmtbus', lock=True)
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    if result is None:
        return jsonify(error={'message': 'Not Found'}), 404

    return jsonify(result=result)


@BLUEPRINT.route('/pipelines', methods=['GET'], read_write=False)
def get_pipelines():
    try:
        result = _get_stanza('pipelines', lock=True)
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    if result is None:
        return jsonify(error={'message': 'Not Found'}), 404

    return jsonify(result=result)


@BLUEPRINT.route('/pipelines', methods=['PUT'], read_write=False)
def set_pipelines():
    try:
        body = request.get_json()
    except Exception as e:
        return jsonify(error={'message': str(e)}), 400

    try:
        if 'version' not in body:
            raise ValueError('version is required')
        version = MMConfigVersion(version=body.pop('version'))

        result = _set_stanza_with_lock(
            'pipelines',
            body,
            version
        )

    except VersionMismatchError:
        return jsonify(error={'message': 'version mismatch'}), 409
    except Exception as e:
        LOG.exception('exception is _set_stanza_with_lock')
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=result)


@BLUEPRINT.route('/node', methods=['POST'], read_write=False)
def create_node():
    try:
        body = request.get_json()
    except Exception as e:
        return jsonify(error={'message': str(e)}), 400

    try:
        result = _create_node(body, lock=True)
    except VersionMismatchError:
        return jsonify(error={'message': 'version mismatch'}), 409
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=result)


@BLUEPRINT.route('/node/<node_id>', methods=['GET'], read_write=False)
def get_node(node_id):
    try:
        result = _get_stanza('node:{}'.format(node_id), lock=True)
    except Exception as e:
        LOG.exception('error in get_node')
        return jsonify(error={'message': str(e)}), 500

    if result is None:
        return jsonify(error={'message': 'Not Found'}), 404

    return jsonify(result=result)


@BLUEPRINT.route('/node/<node_id>', methods=['PUT'], read_write=False)
def set_node(node_id):
    try:
        body = request.get_json()
    except Exception as e:
        return jsonify(error={'message': str(e)}), 400

    try:
        result = _set_node(node_id, body, lock=True)
    except VersionMismatchError:
        return jsonify(error={'message': 'version mismatch'}), 409
    except Exception as e:
        LOG.exception('exception is _set_node')
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=result)


@BLUEPRINT.route('/node/<node_id>', methods=['DELETE'], read_write=False)
def delete_node(node_id):
    version = request.args.get('version', None)
    if version is None:
        return jsonify(error={'message': 'version required'}), 400

    try:
        result = _delete_node(node_id, version, lock=True)
    except VersionMismatchError:
        return jsonify(error={'message': 'version mismatch'}), 409
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

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


def init_app(app):
    app.before_first_request(_init_config)
