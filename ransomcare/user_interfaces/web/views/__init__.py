#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask

ctx = {}
app = Flask(__name__)

from .api import api

app.register_blueprint(api, url_prefix='/api')
