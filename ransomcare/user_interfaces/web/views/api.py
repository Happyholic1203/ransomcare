#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging

from flask import Blueprint, Response

from .. import ctx

logger = logging.getLogger(__name__)
api = Blueprint('api', __name__)


@api.route('/shutdown')
def _shutdown():
    ctx['sniffer'].stop()  # shutdown main loop
    logger.info('Flask down')
    return 'OK'


@api.route('/processes')
def engine():
    body = json.dumps(ctx['engine'].pid_profiles)
    resp = Response(response=body, status=200, mimetype='application/json')
    return resp


@api.route('/events')
def ransom_events():
    body = json.dumps(ctx['events'])
    return Response(response=body, status=200, mimetype='application/json')


@api.route('/sniffer')
def sniffer():
    body = json.dumps(ctx['sniffer'].files)
    return Response(response=body, status=200, mimetype='application/json')
