#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from flask import render_template, Blueprint

from .. import app

logger = logging.getLogger(__name__)

index = Blueprint('index', __name__)


@app.route('/')
def index_page():
    return render_template('index.html')
