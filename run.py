#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from datetime import datetime

import ransomcare

if __name__ == "__main__":
    log_file = datetime.now().strftime('logs/%Y-%m-%d_%H:%M:%S.log')

    if len(sys.argv) == 2 and sys.argv[1] in ('-d', '--debug'):
        from ransomcare.config import dev
        config = dev
    else:
        from ransomcare.config import prod
        config = prod

    ransomcare.main(log_file=log_file, config=config)
