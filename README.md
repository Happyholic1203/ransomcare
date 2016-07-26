# RansomCare
RansomCare is a crypto ransomware detection &amp; prevention software.

Currently it supports only **MacOS**, but its design aims to provide cross-platform support.

RansomCare is in its early stage, and everyone is welcome to extend it and port it to other platforms.

# Running
To run ransomcare:
```bash
git clone https://github.com/Happyholic1203/ransomcare
cd ransomcare
pip install -r requirements  # (mkvirtualenv if you want)
sudo python run.py  # run with `--debug` to see more information

# in another shell
open localhost:8888
```

With `http://localhost:8888` open in your browser,
you'll be notified when crypto ransom events occur,
and you will be prompted if you want to kill the suspicious process (ransomware) or not.

Please leave `http://localhost:8888` open,
otherwise your suspended process(es) won't have a chance to resume or get killed.

RansomCare doesn't have a UI yet, but you can inspect its status by:
```bash
curl http://localhost:8888/api/processes  # suspicious processes
curl http://localhost:8888/api/events  # detected crypto ransom events
```

Please be noted that ransomcare is in its early stage,
and **it may sometimes have some false alarms**,
and it may suspend your normal apps.

Please use with care.

# How it Works
RansomCare *sniffs* critical syscalls using [DTrace](http://dtrace.org/blogs/about/),
and it judges from process behaviors to see if it's a crypto ransomware.

Critical syscalls include: `open`, `getdirentries`, `read`, `write`, `close`, `unlink`.

Crypto ransomwares must perform the following syscalls in order to perform encryption to your files:

1. `getdirentries`: so it knows where and what the files are
2. `open`
3. `read`
4. `write`
5. `close` or `unlink`: `close` to overwrite the original file, `unlink` to write encrypted content to new file

We monitor those syscalls to see if there's any process performing those syscalls in the above order.

For more information, please refer to the [my slides in HITCON Community 2016](https://www.dropbox.com/s/60fn8ot8eylv4cv/HITCON2016%20-%20%E5%8B%92%E7%B4%A2%E8%BB%9F%E9%AB%94%E8%A1%8C%E7%82%BA%E5%81%B5%E6%B8%AC%20%28public%29.pdf?dl=0).

# Sniffing Tools that RansomCare Uses

## [DTrace](http://dtrace.org/blogs/about/) on MacOS
RansomCare sniffs syscalls using [DTrace](http://dtrace.org/blogs/about/),
a tool that is included by default in various operating systems,
including Solaris, FreeBSD, and MacOS.

DTrace provides a variety of *probes*,
each of which can be used to trace different system events,
such as syscalls, io events, etc.

# Road Map

* Implement UI
* Support for Windows
* Implement whitelist

# Contribution

Please open issues if you encounter anything unpleasent.

Please send pull requests if you improved it.
