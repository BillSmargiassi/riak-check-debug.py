# riak-check-debug.py
A diagnostic tool to report on logs produced by `riak-debug`

# requirements

You need a Python installation (https://www.python.org/downloads/).

Tested against Python 2.7.12.

# install

Retrieve the script with `wget`:

```shell
wget https://raw.githubusercontent.com/shaneutt/riak-check-debug.py/master/riak-check-debug.py
chmod +x riak-check-debug.py
```

Place it somewhere in your `$PATH`.

# usage

In the most basic case run `riak-check-debug.py -d $LOGDIR` where `$LOGDIR` is the directory where you've extracted your `riak-debug` archives.

Run `riak-check-debug.py -h` for help:

```shell
usage: riak-check-debug.py [-h] [-f FILES [FILES ...]] [-d DIRS [DIRS ...]]
                           [-l] [-tar TAR_MODE [TAR_MODE ...]] [--no-collapse]
                           [--no-combine-logs] [--no-old-warnings]

optional arguments:
  -h, --help            show this help message and exit
  -f FILES [FILES ...], --files FILES [FILES ...]
                        one or more files to parse
  -d DIRS [DIRS ...], --dirs DIRS [DIRS ...]
                        one or more directories to find files to parse
  -l, --log-report      log the entire report to a file instead of printing to
                        stdout
  -tar TAR_MODE [TAR_MODE ...], --tar-mode TAR_MODE [TAR_MODE ...]
                        use tarballs instead of extracted files for the
                        reports
  --no-collapse         disable "collapsing" of multiple redudant lines
                        (warning: spammy)
  --no-combine-logs     disable combined console and error logs
  --no-old-warnings     turn off warnings for old debugs
```
