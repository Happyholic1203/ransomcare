#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
import ransomcare

if __name__ == "__main__":
    log_file = datetime.now().strftime('logs/%Y-%m-%d_%H:%M:%S.log')
    ransomcare.main(log_file=log_file)
