from time import time

import ujson as json
from blinker import signal

from . import config


def _send_status_signal(source, status):
    s = signal('mm-status')
    if not bool(s.receivers):
        return

    s.send(
        source,
        data={
            'status': status,
            'timestamp': int(time()*1000)
        }
    )


def _running_config_changed():
    _send_status_signal(
        source='<running-config>',
        status='changed'
    )


def _committed_config_changed():
    _send_status_signal(
        source='<committed-config>',
        status='changed'
    )


def _prototypes_changed():
    _send_status_signal(
        source='<prototypes>',
        status='changed'
    )


def init_paths(monitored_paths):
    monitored_paths.add_listener(
        config.get('MINEMELD_CONFIG_PATH'),
        listener=_running_config_changed,
        match='^running-config\.yml$'
    )
    monitored_paths.add_listener(
        config.get('MINEMELD_CONFIG_PATH'),
        listener=_running_config_changed,
        match='^pipelines\.yml$'
    )
    monitored_paths.add_listener(
        config.get('MINEMELD_CONFIG_PATH'),
        listener=_committed_config_changed,
        match='^committed-config\.yml$'
    )
    for path in config.get('MINEMELD_PROTOTYPE_PATH').split(':'):
        monitored_paths.add_listener(
            path,
            listener=_prototypes_changed,
            match='^.*\.yml$'
        )
