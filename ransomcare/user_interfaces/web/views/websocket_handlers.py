#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from .. import socketio
from .... import event

logger = logging.getLogger(__name__)


@socketio.on('connected')
def connected(message):
    logger.info('Websocket client connected: %r' % message)
    socketio.emit('debug', 'connected with server')


@socketio.on('prompt_answer')
def prompt_answer(data):
    prompt_id = data.get('id')
    answer = data.get('answer')
    if prompt_id == 'KILL_OR_NOT':
        pid = data['data']['pid']
        cmdline = data['data']['cmdline']
        if answer:
            event.EventUserDenyProcess(pid, cmdline).fire()
            socketio.emit('flash', 'Killing PID: %d' % pid)
        else:
            event.EventUserAllowProcess(pid, cmdline).fire()
