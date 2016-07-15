#!/usr/bin/env python
# -*- coding: utf-8 -*-


class UI(object):
    def on_ask_user_allow_or_deny(self, evt):
        raise NotImplementedError()

from .web import WebUI
from .console import ConsoleUI
from .darwin import DarwinAppUI
