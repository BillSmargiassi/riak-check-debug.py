#!/usr/bin/env python
import argparse, re, sys
from datetime import datetime

# args and defaults
parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', required=True)
parser.add_argument('-m', '--min-occurrences', default=1)
parser.add_argument('-i', '--ignore', nargs='+', default=[])
parser.add_argument('-t', '--timeframe', nargs=2, default=[])
parser.add_argument('-nn', '--no-nodenames', action='store_true')
args = vars(parser.parse_args())

# ADD NEW RULES HERE
replacements = [
    # timestamps and Erlang pids
    ('^[0-9-]+\s[0-9:.]+\s', ''),
    ('<\d+\.\d+\.\d+>', ''),
    # AAE
    ('Starting AAE tree build: [0-9]+', 'Starting AAE tree build: **PARTITION_ID**'),
    ('Clearing AAE tree: [0-9]+', 'Clearing AAE tree: **PARTITION_ID**'),
    ('Finished AAE tree build: [0-9]+', 'Finished AAE tree build: **PARTITION_ID**'),
    ('Repaired [0-9]+ keys during active anti-entropy exchange of .*', 'Repaired some keys during anti-entropy exchange'),
    # Heap
    ('monitor large_heap  \[{initial_call,{erlang,apply,2}}.*', 'monitor large_heap {initial_call,{erlang,apply,2}}'),
    # Unrecognized Messages
    ('Unrecognized message {[0-9]+,{ok,{r_object.*', 'Unrecognized message: {ok, r_object...'),
    ('Unrecognized message {[0-9]+,{error,timeout.*', 'Unrecognized message: {error, timeout}'),
    ('Unrecognized message {[0-9]+,ok.*', 'Unrecognized message: ok'),
    # Handoff
    ('hinted transfer of riak_kv_vnode .* failed because of exit:{{nodedown,.*', 'hinted transfer of vnode failed because of nodedown'),
    ('hinted transfer of riak_kv_vnode from .* failed because of enotconn', 'hinted transfer of vnode failed because of enotconn'),
    ('An outbound handoff of partition riak_kv_vnode [0-9]+ was terminated for reason: {shutdown,{error,enotconn}}.*', 'Outbound handoff of partition terminated due to enotconn'),
    ('ownership transfer of riak_kv_vnode .* failed because of TCP recv timeout', 'ownership transfer failed because of TCP recv timeout'),
]

if args['no_nodenames']:
    replacements.append(('\(.*\@[0-9.]+\) ', ''))

# determine timeframe, if any
if len(args['timeframe']) == 2:
    try:
        # allow mix-and-match of different timestamps
        if len(args['timeframe'][0]) == 10:
            args['timeframe'][0] = datetime.strptime(args['timeframe'][0], '%Y-%m-%d')
        elif len(args['timeframe'][0]) == 19:
            args['timeframe'][0] = datetime.strptime(args['timeframe'][0], '%Y-%m-%d %H:%M:%S')
        else:
            args['timeframe'][0] = datetime.strptime(args['timeframe'][0], '%Y-%m-%d %H:%M:%S.%f')

        if len(args['timeframe'][1]) == 10:
            args['timeframe'][1] = datetime.strptime(args['timeframe'][1], '%Y-%m-%d')
        elif len(args['timeframe'][1]) == 19:
            args['timeframe'][1] = datetime.strptime(args['timeframe'][1], '%Y-%m-%d %H:%M:%S')
        else:
            args['timeframe'][1] = datetime.strptime(args['timeframe'][1], '%Y-%m-%d %H:%M:%S.%f')
    except ValueError as e:
        sys.stderr.write("ERROR: %s\n" % e)
        sys.exit(2)
    else:
        # make sure a bad timeframe wasn't supplied
        if args['timeframe'][0] > args['timeframe'][1]:
            sys.stderr.write("start time is after end time\n")
            sys.exit(3)

# determine which lines should be ignored
ignores = []
for ignore in args['ignore']:
    pattern = re.compile(ignore)
    ignores.append(pattern)

# line storage
lines = {}

def main():
    try:
        # run replacements on all lines
        log = open(args['file'])
        for line in log.readlines():
            for ignore in ignores:
                # check for ignores
                if ignore.search(line):
                    break
            else:
                clean(line)
        log.close()
    except IOError as e:
        sys.stderr.write("%s\n" % e)
        sys.exit(3)
    # TODO uncaught

    # print each line unless count doesn't match, sort with highest occurrence first
    for line in sorted(lines, key=lines.get, reverse=True):
        count = int(lines[line])
        if count >= int(args['min_occurrences']):
            sys.stdout.write("%d:\t%s" % (count, line))

def clean(line):
    # check the timeframe
    if len(args['timeframe']) == 2:
        dt = datetime.strptime(line[0:19], "%Y-%m-%d %H:%M:%S")
        if dt < args['timeframe'][0] or dt > args['timeframe'][1]:
            return

    # run the replacements
    for replacement in replacements:
        line = re.sub(replacement[0], replacement[1], line)

    # trim the line
    if len(line) > 175:
        line = (line[:175] + "..\n")

    # build the count
    if line in lines:
        lines[line] = lines[line] + 1
    else:
        lines[line] = 1

# start
main()
