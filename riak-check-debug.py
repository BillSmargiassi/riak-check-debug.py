#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##-----------------------------------------------------------------------------
## A diagnostic tool to report on logs produced by riak-debug.
##
## Riak KV can produce "debug" archives with `riak-debug`. These archives
## contain configuration and log files that describe the state of a Riak node.
##
## This tool parses extracted archives for a set of known bad configurations
## and log entries and produces reports based on its findings.
##
## This tool can also combine the error.log and console.log files of several
## debug outputs to create a large rolling long of all the activity in a
## cluster.
##-----------------------------------------------------------------------------
import argparse, datetime, glob, json, os, os.path, re, sys, tarfile, time
from collections import defaultdict

##-----------------------------------------------------------------------------
## "mainconfig" is a data-structure that informs the reports what files to
## check, and what patterns to look for in those files. From this data the end
## report is built from categories and pattern descriptions.
##
## If you are interested in adding more reports, this is where you would start.
##
## ---
##
## Tutorial:
##
## To begin extending this program, consider a new report you'd like to add.
##
## The following elements should be considered:
##
##  * What is the category of this report?
##
##  Does the report pertain to a category that already exists, like 'LevelDB Report'?
##
##  * What files will contain the information I want to report on?
##
##  Devise a regex pattern that will match those files given full path to the file.
##
##  * What strategy will I use?
##
##      * count strategy: used for counting matches and creating a numeric report
##      * match strategy: used to print the entire line out for every match
##      * submatch strategy: given a regex pattern with groups, print a report with your own format for every match
##      * unique strategy: given a regex pattern with groups, consider the first group "unique" and print a report only once for every match that contains it
##
##  ---
##
## From the above information you can create a new entry (or edit an existing one) with the following format (in mainconfig):
##
##  'NAME OF YOUR REPORT': {
##      'FILE PATTERN TO MATCH': { # this is how to include one or more files into your search
##          'STRATEGY': {
##              'PATTERN1': 'DESCRIPTION', # the pattern of the line in the file you want to match, and the description of what is being matched for reporting purposes
##              'PATTERN2': 'DESCRIPTION',
##          },
##          'ANOTHER_STRATEGY': { # you can have multiple strategies for each category and file match
##              [...]
##          }
##      },
##      'ANOTHER FILE YOU WANT TO MATCH': { # you can match multiple files and repeat the above structure for every file
##          [...]
##      }
##  },
##  'ANOTHER NAME OF ANOTHER REPORT': { # you can have multiple reports with different names, they can even cover the same files as other reports!
##      [...]
##  }
##-----------------------------------------------------------------------------
mainconfig = {
    'LevelDB Report': {
        '/LOG$': {
            'count': {
                'Compaction error': 'Found LevelDB Compaction Errors',
                'waiting': 'Found LevelDB Stalls'
            }
        }
    },
    'Virtual Memory Report': {
        'commands/sysctl|commands/sysctl_linux': {
            'submatch': {
                'vm.swappiness = ([1-9]\\d*)': 'Found Non-Zero vm.swappiness in %s:\n\tvm.swappiness = %s',
                'vm.overcommit_memory = ([1-9]\\d*)': 'Found Non-Zero vm.overcommit_memory in %s:\n\tvm.overcommit_memory = %s',
                '(vm\.dirty.*ratio) = ([1-9]\\d*)': 'Found Non-Zero vm.dirty ratio in %s:\n\t%s = %s'
            }
        }
    },
    'Linux Network Stack Report': {
        'commands/sysctl|commands/sysctl_linux': {
            'submatch': {
                'net.core.rmem_default = ([0-9]{0,6}\s+|[0-7][0-9]{0,6}\s+|8[0-2][0-9]{0,5}\s+)': 'Found LOW net.core.rmem_default (should be at least 8388608) in %s:\n\tnet.core.rmem_default = %s',
                'net.core.rmem_max = ([0-9]{0,6}\s+|[0-7][0-9]{0,6}\s+|8[0-2][0-9]{0,5}\s+)': 'Found LOW net.core.rmem_max (should be at least 8388608) in %s:\n\tnet.core.rmem_max = %s',
                'net.core.wmem_default = ([0-9]{0,6}\s+|[0-7][0-9]{0,6}\s+|8[0-2][0-9]{0,5}\s+)': 'Found LOW net.core.wmem_default (should be at least 8388608) in %s:\n\tnet.core.wmem_default = %s',
                'net.core.wmem_max = ([0-9]{0,6}\s+|[0-7][0-9]{0,6}\s+|8[0-2][0-9]{0,5}\s+)': 'Found LOW net.core.wmem_max (should be at least 8388608) in %s:\n\tnet.core.wmem_max = %s',
                'net.core.netdev_max_backlog = ([0-9]{0,4}\s+)': 'Found LOW net.core.netdev_max_backlog (should be at least 10000) in %s:\n\tnet.core.netdev_max_backlog = %s',
            },
        }
    },
    'Memory Report': {
        'commands/dmesg|commands/messages|commands/meminfo': {
            'count': {
                'invoked oom-killer': 'Found OOM-Killer Invocations',
                'AnonHugePages:\s+[1-9]\d*': 'Found Transparent Huge Page Usage'
            }
        }
    },
    'System Report': {
        'commands/schedulers': {
            'match': {
                '\[cfq\]': 'CFQ (Completely Fair Queueing)'
            }
        }
    },
    'Riak Error Log Report': {
        'platform_log_dir/error.log': {
            'count': {
                'emfiles': 'Found file handle exhaustion (emfiles)',
                'system_limit': 'Found Erlang resource exhaustion (system_limit)',
                'Corruption': 'Found AAE Hashtree Corruption'
            },
            'match': {
                    'no CRL': 'CRL Checking Enabled or is Invalid',
                    'certificate unknown': 'Verify Correctness of Configured Certificates (Generation, Configuration, Client Usage)'
            }
        }
    },
    'Riak Console Log Report': {
        'platform_log_dir/console.log': {
            'count': {
                'Read(ing)? large object': 'Found reports of reading large objects', # "Reading" is 1.4.8 syntax
                'Too many siblings': 'Found reports of objects with too many siblings'
            },
            'unique': {
                'Read large object (<<\"?.*\"?>>/<<\"?.*\"?>>) \(([0-9]+) bytes\)': {
                    'description': 'Large Object',
                    'format': '%s (%s) bytes',
                    'replace': [('<', ''), ('>', ''), ('"', '')]
                },
                'Reading large object of size ([0-9]+) from (<<\"?.*\"?>>/<<\"?.*\"?>>)': { # Riak 1.4.8 syntax
                    'description': 'Large Object',
                    'format': '(%s) bytes %s',
                    'replace': [('<', ''), ('>', ''), ('"', '')]
                },
                'Too many siblings for object (<<\"?.*\"?>>/<<\"?.*\"?>>) (\([0-9]+\))': {
                    'description': 'Object with too many siblings',
                    'format': '%s has %s siblings',
                    'replace': [('<', ''), ('>', ''), ('"', '')]
                }
            }
        }
    },
    'Bitcask Report': {
        'platform_log_dir/console.log': {
            'submatch': {
                "Hintfile ('.*') invalid": "Found invalid hintfile in %s:\n\thintfile: %s"
            }
        }
    },
    'Config Report': {
        'config/riak.conf$': {
            'match_compare': {
                'storage_backend = *': 'Found differing backend configurations'
            }
        }
    },
    'Network Report': {
        'commands/netstat': {
            'count': {
                'TIME_WAIT': 'Found suspended network connections'
            }
        }
    }
}

## Link docs to report categories
docs = {
    'Linux Network Stack Report': ['http://docs.basho.com/riak/kv/latest/using/performance/#kernel-and-network-tuning']
}

##-----------------------------------------------------------------------------
## Global Variables
##-----------------------------------------------------------------------------

## arguments parsed with argparser
args = {}

## stores a list of the base directories provided in args
baseDirs = []

## files for processing
files = []

## files collated for processing as a group
match_compare_groups = {}

## directory to log all files to
logdir = 'riak-check-debug-logs-' + str(datetime.datetime.now()).replace(' ', '_').replace(':', '.')

## all the report data built for logging and display
report = defaultdict()

## directories where the application logs live
riakKVDebugDirs = []
riakCSDebugDirs = []

## if tar_mode is used, holds the lists of files present in a tarfile
tarballs = []
tarfiles = defaultdict()

##-----------------------------------------------------------------------------
## Main & Setup Functions
##-----------------------------------------------------------------------------

def main():
    ## build the args and setup defaults, check for files
    setup()

    ## optional: report on old riak-debug directories
    if not args.no_old_warnings:
        check_for_old_debugs()

    ## optional: combine error.log and console.log files
    if not args.no_combine_logs:
        build_combined_riakcs_logs()
        build_combined_riakkv_logs()

    ## loop over files and pattern match on them
    for filename in files:
        config = get_file_config(filename)
        for category in config.keys():
            for strategy in config[category].keys():
                patterns = config[category][strategy]
                run_strategy(filename, category, strategy, patterns)
    
    ## loop over file groups
    for category in match_compare_groups.keys():
        filenames = match_compare_groups[category]['filenames']
        strategy = 'match_compare'
        pattern_data = match_compare_groups[category]['pattern_data']
        run_multifile_strategy(filenames, category, strategy, pattern_data)

    ## display/log the end result
    reporter()

def setup():
    """parses arguments, sets globals, and builds options"""

    global args

    ## build a parser and generate
    parser = argparse.ArgumentParser('riak-check-debug.py')
    parser.add_argument('-f', '--files', nargs='+', help='one or more files to parse', type=str, default=[])
    parser.add_argument('-d', '--dirs', nargs='+', help='one or more directories to find files to parse', type=str, default=[])
    parser.add_argument('-l', '--log-report', help='log the entire report to a file instead of printing to stdout', action='store_true')
    parser.add_argument('-tar', '--tar-mode', nargs='+', help='use tarballs instead of extracted files for the reports', type=str, default=[])
    parser.add_argument('--no-collapse', help='disable "collapsing" of multiple redudant lines (warning: spammy)', action='store_true')
    parser.add_argument('--no-combine-logs', help='disable combined console and error logs', action='store_true')
    parser.add_argument('--no-old-warnings', help='turn off warnings for old debugs', action='store_true')
    args = parser.parse_args()

    ## ensure that we've been provided at least a list of files or dirs
    if not args.files and not args.dirs and not args.tar_mode:
        parser.error('one of -f, -d, or -tar must be provided')

    ## ensure that each file provided exists
    for f in args.files:
        if not os.path.isfile(f):
            error("no such file: %s" % (f))

    ## walk any directories to build a list of files
    global baseDirs
    baseDirs = args.dirs
    dirfiles = []
    for d in baseDirs:
        for root, dirs, filelist in os.walk(d):
            for f in filelist:
                dirfiles.append(root + '/' + f)

    ## list the tarballs provided
    global tarballs
    for e in args.tar_mode:
        if os.path.isdir(e):
            e = glob.glob(e + '/*-riak-debug.tar.gz')
            tarballs = tarballs + e
        else:
            if re.search(r'riak-debug.tar.gz', e):
                tarballs.append(e)
            else:
                parser.error("%s is not a valid tarball! Should look like *-riak-debug.tar.gz" % (e))

    ## create parsers for each tarball
    global tarfiles
    for tarball in tarballs:
        root, name = os.path.split(tarball)
        name = name.replace('.tar.gz', '')
        tarfiles[name] = tarfile.open(tarball)

    ## get all the files from each tarball
    tarfile_names = []
    for tar in tarfiles.values():
        tarfile_names = tarfile_names + filter(lambda x: not re.search(r'/\.info/', x), tar.getnames())

    ## store the files to operate on
    global files
    files = args.files + dirfiles + tarfile_names

    ## ensure that some files were provided either with -f or -d
    if not files:
        parser.error('no files found')

    ## get any dirs that look like riak-debug dirs
    global riakKVDebugDirs
    for directory in baseDirs:
        newRiakDirs = glob.glob(os.path.join(directory, "*-riak-debug"))
        riakKVDebugDirs = riakKVDebugDirs + newRiakDirs
    if not riakKVDebugDirs and not args.tar_mode:
        warning('found no *-riak-debug directories')

    ## get any dirs that look like riak-cs-debug dirs
    global riakCSDebugDirs
    for directory in baseDirs:
        newCSDirs = glob.glob(os.path.join(directory, "*-riak-cs-debug"))
        riakCSDebugDirs = riakCSDebugDirs + newCSDirs

    ## set up the categories
    for category in mainconfig.keys():
        report[category] = defaultdict(dict)

def check_for_old_debugs():
    """look for riak-debug directories that are older than 6 hours and warn the user"""

    thisreport = 'Debug Archive Age Report'
    for directory in riakKVDebugDirs + tarballs:
        mtime = os.path.getmtime(directory)
        now = datetime.datetime.utcnow()
        then = datetime.datetime.utcfromtimestamp(mtime)
        elapsed = now - then
        if elapsed.seconds > 21600: # 6 hours
            if not thisreport in report:
                report[thisreport] = {}
            if not thisreport in report[thisreport]:
                report[thisreport][thisreport] = {}
            if not 'plain' in report[thisreport][thisreport]:
                report[thisreport][thisreport]['plain'] = []
            report[thisreport][thisreport]['plain'].append("WARNING: %s (last updated %s UTC): debug may be old" % (directory, str(then)))

def build_combined_riakcs_logs():
    """combine all console.log and error.log files found for Riak CS"""

    if riakCSDebugDirs:
        header("Generating Combined Riak CS Logs")
        build_combine_logs('riakcs', 'riak-cs-debug', riakCSDebugDirs)

def build_combined_riakkv_logs():
    """combine all console.log and error.log files found for Riak KV"""

    if riakKVDebugDirs:
        header("Generated Combined Riak KV Logs")
        build_combine_logs('riakkv', 'riak-debug', riakKVDebugDirs)

## a list of console.log events that are considered "spammy"
spamEvents = [
    'Too many siblings',
    'Unrecognized message',
    'perhaps_log_throttle_change',
    'Heartbeat is misconfigured',
    'monitor long_schedule',
    '{shutdown,max_concurrency}',
    "There's no NAT mapping"
]

def build_combine_logs(application, pattern, directories):
    """combine all console.log and error.log files found for an application"""

    consoleLogFiles = []
    errorLogFiles = []
    if args.tar_mode:
        for filename in files:
            if re.search(pattern + '/logs/platform_log_dir/console.log', filename):
                consoleLogFiles.append(filename)
            if re.search(pattern + '/logs/platform_log_dir/error.log', filename):
                errorLogFiles.append(filename)
    else:
        for directory in directories:
            consoleLogFiles = consoleLogFiles + glob.glob(directory + '/logs/platform_log_dir/console.log*')
            errorLogFiles = errorLogFiles + glob.glob(directory + '/logs/platform_log_dir/error.log*')

    filenameRE = re.compile('([^/]*)-' + pattern)
    loglineRE = re.compile('^([0-9-]+\s+[0-9:]+[0-9.]+)\s+(.*)$')

    ## build the combined console log
    consoleLog = build_log(filenameRE, loglineRE, consoleLogFiles)
    consoleLogOut = application + '-combined-console.log'
    log2file(consoleLogOut, consoleLog)
    info("%s written to:\n\t%s/%s" % (consoleLogOut, logdir, consoleLogOut))
    space()

    ## build the nospam combined console log
    filterRE = re.compile('|'.join(spamEvents))
    consoleLogNoSpam = filter(lambda x: not filterRE.search(x), consoleLog)
    consoleLogNoSpamOut = application + '-combined-console.log.nospam'
    log2file(consoleLogNoSpamOut, consoleLogNoSpam)
    info("%s written to:\n\t%s/%s" % (consoleLogNoSpamOut, logdir, consoleLogNoSpamOut))
    space()

    ## build the combined error log
    errorLog = build_log(filenameRE, loglineRE, errorLogFiles)
    errorLogOut = application + '-combined-error.log'
    log2file(errorLogOut, errorLog)
    info("%s written to:\n\t%s/%s" % (errorLogOut, logdir, errorLogOut))
    space()

def build_log(filenameRE, loglineRE, logFiles):
    """build a combined log given search parameters and files to parse"""

    combinedLog = []
    for filename in logFiles:
        search1 = filenameRE.search(filename)
        if search1:
            node, = search1.groups()
            filehandle = get_file(filename)
            for line in filehandle.readlines():
                search2 = loglineRE.search(line)
                if search2:
                    linedate, content = search2.groups()
                    combinedLog.append("%s (%s) %s\n" % (linedate, node, content))

    return sorted(combinedLog)

##-----------------------------------------------------------------------------
## Strategy Functions
##-----------------------------------------------------------------------------

def run_strategy(filename, category, strategy, pattern_data):
    """run a specific strategy by name"""

    ## extract the configuration data and patterns
    patterns = pattern_data.keys()
    global match_compare_groups

    if strategy == 'count':
        matches = do_count_matches(filename, patterns)
        if matches:
            run_count_strategy(filename, category, pattern_data, matches)
    elif strategy == 'match_compare':
        empty = {'pattern_data': pattern_data, 'filenames': []}
        match_compare_groups.setdefault(category, empty)['filenames'].append(filename)
    else:
        matches = do_matches(filename, patterns)
        if matches:
            if strategy == 'match':
                run_match_strategy(filename, category, pattern_data, matches)

            if strategy == 'submatch':
                run_submatch_strategy(filename, category, pattern_data, matches)

            if strategy == 'unique':
                run_unique_strategy(filename, category, pattern_data, matches)

def run_multifile_strategy(filenames, category, strategy, pattern_data):
    if len(filenames) < 2: return
    if strategy == 'match_compare':
        run_match_compare_strategy(filenames, category, pattern_data)

## The Match-Compare strategy looks for lines in files that match the specified pattern.
## It then collates these lines and compares them for string equality.
## If any are different or missing, it reports the line or lack for all files.
def run_match_compare_strategy(filenames, category, pattern_data):
    patterns = pattern_data.keys()
    matches_dict = {}
    for filename in filenames:
        matches_dict[filename] = do_matches(filename, patterns)
    ##print(matches_dict)
    for pattern in patterns:
        description = pattern
        collated = []
        for filename in filenames:
            found_pattern = False
            for item in matches_dict[filename]:
                if item['pattern'] == pattern:
                    found_pattern = True
                    collated.append((filename, item['line']))
            if found_pattern == False:
                collated.append((filename, '***MISSING***\n'))
        ##print(collated)
        mismatch = False
        for (name, line) in collated:
            if not line == collated[0][1]:
                ##print('mismatch found: %s != %s' % (line, collated[0]))
                mismatch = True
        ##print('mismatch == %s' % (mismatch))
        if mismatch == True:
            newline = "\"%s\" not identical in all files!\n" % (description)
            for (name, line) in collated:
                newline += "\t%s : %s" % (name, line)
            ## build the report
            if not 'match_compare' in report[category][description]:
                report[category][description]['match_compare'] = [newline]
            else:
                report[category][description]['match_compare'].append(newline)


def run_count_strategy(filename, category, pattern_data, matches):
    """process a list of matches into a report for a 'count' type report"""

    for pattern in matches.keys():
        ## get the configuration data for building the report
        description = pattern_data[pattern]
        total = matches[pattern]

        ## build the report
        if 'count' in report[category][description]:
            report[category][description]['count'] += total
        else:
            report[category][description]['count'] = total

def run_match_strategy(filename, category, pattern_data, matches):
    """process a list of matches into a report for a 'match' type report"""

    for data in matches:
        ## get the configuration data for building the report
        pattern = data['pattern']
        line = data['line']
        submatches = data['submatches']
        description = pattern_data[pattern]
        content = (filename,) + submatches
        newline = "%s found in %s\n\t%s" % (description, filename, line)

        ## build the report
        if not 'match' in report[category][description]:
            report[category][description]['match'] = [newline]
        else:
            report[category][description]['match'].append(newline)

def run_submatch_strategy(filename, category, pattern_data, matches):
    """process a list of matches into a report for a 'submatch' type report"""

    for data in matches:
        ## get the configuration data for building the report
        pattern = data['pattern']
        line = data['line']
        submatches = data['submatches']
        description = pattern_data[pattern]
        content = (filename,) + submatches

        ## build the report
        if not 'submatch' in report[category][description]:
            report[category][description] = {
                'submatch': [description % content]
            }
        else:
            report[category][description]['submatch'].append(description % content)

def run_unique_strategy(filename, category, pattern_data, matches):
    """process a list of matches into a report for a 'unique' type report"""

    for data in matches:
        ## get the configuration data for building the report
        pattern = data['pattern']
        line = data['line']
        submatches = data['submatches']
        description = pattern_data[pattern]['description']
        printformat = pattern_data[pattern]['format']
        content = printformat % submatches
        identifier = submatches[0]

        ## build the report
        if 'replace' in pattern_data[pattern]:
            for char, repl in pattern_data[pattern]['replace']:
                content = content.replace(char, repl)

        if not 'unique' in report[category][description]:
            report[category][description]['unique'] = {}

        report[category][description]['unique'][identifier] = content

##-----------------------------------------------------------------------------
## Regex Functions
##-----------------------------------------------------------------------------

def do_matches(filename, patterns):
    """provided a filename and a list of patterns search each line for a match and return the matches"""

    ## open the file and compile all regex += 1
    fileh = get_file(filename)
    regexes = map(lambda p: re.compile(p), patterns)

    matches = []
    for line in fileh:
        for regex in regexes:
            search = regex.search(line)
            if search:
                matches.append({
                    'line': line,
                    'submatches': search.groups(),
                    'pattern': regex.pattern
                })

    return matches

def do_count_matches(filename, patterns):
    ## open the file and compile all regex += 1
    fileh = get_file(filename)
    regexes = map(lambda p: re.compile(p), patterns)

    matches = {}
    for line in fileh:
        for regex in regexes:
            search = regex.search(line)
            if search:
                if regex.pattern in matches:
                    matches[regex.pattern] += 1
                else:
                    matches[regex.pattern] = 1

    return matches

##-----------------------------------------------------------------------------
## Logging/Reporting Functions
##-----------------------------------------------------------------------------

def lager(category, lines):
    """given a category print or log lines"""

    numlines = len(lines)
    if numlines > 2 and not args.no_collapse and not args.log_report:
        ## determine logfile and log lines
        logfile = logdir + '/' + category.replace(' ', '') + '.log'
        log2file(logfile, lines)

        ## inform the user of the logfiles
        warning(lines[0])
        infowarn("\t=> encountered %s of the above, logged to %s" % (str(numlines), logfile))
    else:
        for subreport in lines:
            warning(subreport)

def log2file(logfile, lines):
    """write a list of lines to a logfile in logdir"""

    if not isinstance(lines, list):
        lines = [lines]

    root, name = os.path.split(logfile)
    if not os.path.isdir(logdir):
        os.makedirs(logdir)

    fileh = open(logdir + '/' + name, "a")
    for line in lines:
        if not line.endswith("\n"):
            line = line + "\n"
        fileh.write(line)

def reporter():
    """display the final report"""

    count = 0
    for category in sorted(report.keys()):
        ## get all the data pertaining to the category
        data = report[category]

        ## print the header for this category
        if count > 0:
            space()
        header("%s" % (category))

        ## find all the parse jobs in the category
        descriptions = sorted(data.keys())
        for description in descriptions:
            descData = data[description]
            for strategy in descData:
                if strategy == 'count':
                    warning("%s: %s" % (description, descData['count']))
                elif strategy == 'unique':
                    lines = map(lambda x: description + ': ' + x, sorted(descData[strategy].values()))
                    lager(category, lines)
                else:
                    lines = descData[strategy]
                    lager(category, lines)

        if len(descriptions) < 1:
            success("Done! Nothing to report!")
        else:
            if category in docs:
                related_docs = docs[category]
                if len(related_docs) > 0:
                    footer("Relevant Docs")
                for doc in related_docs:
                    info(doc)

        count += 1

    space()

    if os.path.isdir(logdir):
        success_stdout("Reports Complete! (Logs available in directory: %s)" % (logdir))
    else:
        success_stdout("Reports Complete!")

##-----------------------------------------------------------------------------
## Print Functions
##-----------------------------------------------------------------------------

## terminal colors for warnings, errors, e.t.c.
class bcolors:
    HEADER = '\033[1;36m'
    OKBLUE = '\033[1;34m'
    OKGREEN = '\033[1;32m'
    WARNING = '\033[1;33m'
    INFOWARN = '\033[1;35m'
    FAIL = '\033[1;31m'
    ENDC = '\033[0m'

def error(msg, code=2):
    print bcolors.FAIL + msg + bcolors.ENDC
    sys.exit(code)

def footer(msg):
    msg = "-- " + msg + " --\n"
    if args.log_report:
        log2file('report.txt', msg)
    else:
        print bcolors.INFOWARN, msg, bcolors.ENDC

def header(msg):
    msg = "= " + msg + " =\n"
    if args.log_report:
        log2file('report.txt', msg)
    else:
        print bcolors.HEADER, msg, bcolors.ENDC

def info(msg):
    msg = "* " + msg
    if args.log_report:
        log2file('report.txt', msg)
    else:
        print bcolors.OKBLUE, msg, bcolors.ENDC

def infowarn(msg):
    if args.log_report:
        log2file('report.txt', msg)
    else:
        print bcolors.INFOWARN, msg, bcolors.ENDC

def space():
    if args.log_report:
        log2file('report.txt', '')
    else:
        print ""

def success(msg):
    msg = "* " + msg
    if args.log_report:
        log2file('report.txt', msg)
    else:
        print bcolors.OKGREEN, msg, bcolors.ENDC

def success_stdout(msg):
    print bcolors.OKGREEN, msg, bcolors.ENDC

def warning(msg):
    msg = "* " + msg
    if args.log_report:
        log2file('report.txt', msg)
    else:
        print bcolors.WARNING, msg, bcolors.ENDC

##-----------------------------------------------------------------------------
## Helper Functions
##-----------------------------------------------------------------------------

def get_file(filename):
    """returns a file object given a file name"""

    if args.tar_mode:
        archive_name = filename.split('/')[0]
        tar = tarfiles[archive_name]
        return tar.extractfile(filename)
    else:
        return open(filename, 'r')

def get_file_config(filename):
    """return the configuration for a file if it matches any described patterns"""

    config = defaultdict(defaultdict)
    for category in mainconfig.keys():
        for file_pattern in mainconfig[category].keys():
            if re.search(file_pattern, filename):
                for strategy in mainconfig[category][file_pattern].keys():
                    config[category][strategy] = mainconfig[category][file_pattern][strategy]

    return config

##--- end ---###
main()
