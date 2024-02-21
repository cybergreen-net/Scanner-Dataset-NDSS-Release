import argparse
import os
import concurrent.futures
import csv
import math
import multiprocessing
import random as random
import subprocess
from datetime import datetime
import urllib.request
import sys

QUERY_TYPES = [
    "A", "AAAA", "AFSDB", "AMTRELAY",
    "ANY", "APL", "ATMA", "AVC",
    "AXFR", "CAA", "CDNSKEY", "CDS",
    "CERT", "CNAME", "CSYNC", "DHCID",
    "DLV", "DNAME", "DNSKEY", "DS",
    "EID", "EUI48", "EUI64", "GID",
    "GPOS", "HINFO", "HIP", "HTTPS",
    "IPSECKEY", "ISDN", "IXFR", "KEY",
    "KX", "L32", "L64", "LOC",
    "LP", "MAILA", "MAILB", "MB",
    "MD", "MF", "MG", "MINFO",
    "MR", "MX", "NAPTR", "NID",
    "NIMLOC", "NINFO", "NS", "NSEC",
    "NSEC3", "NSEC3PARAM", "NULL", "NXT",
    "None", "OPENPGPKEY", "OPT", "PTR",
    "PX", "RKEY", "RP", "RRSIG",
    "RT", "Reserved", "SIG", "SMIMEA",
    "SOA", "SPF", "SRV", "SSHFP",
    "SVCB", "TA", "TALINK", "TKEY",
    "TLSA", "TSIG", "TXT", "UID",
    "UINFO", "UNSPEC", "URI", "X25",
    "ZONEMD", "NSAP-PTR"
]

SERVER_URL = "http://0.0.0.0:{port}/"

MX_COUNT_ENDPOINT = "get-mx-count"

DEFAULT_PORT = "8080"

count = 0


def scan(shardsize_cmd):
    global count
    subprocess.run(shardsize_cmd[1])
    count += 1
    batch_id = math.floor(count / shardsize_cmd[0])
    print(f"Done with scan {count} (batch {batch_id})")


def prepare_subcommand(ctx, date, filename, dir):
    if ctx.binstore.endswith("/"):
        ctx.binstore = ctx.binstore[:-1]

    if ctx.nodate:
        out_dir_path = f'{ctx.output}/{ctx.type}/{dir}'
    else:
        out_dir_path = f'{ctx.output}/{date}/{ctx.type}/{dir}'

    command = [f'{ctx.binstore}/scan',
               ctx.type,
               '--hostname',
               f'{filename}',
               '--json',
               '--out-dir',
               f'{out_dir_path}',
               '--out-file',
               f'{filename}'
               ]
    if ctx.type == 'dns':
        command += ['--query-type', ctx.querytype]
    if ctx.noserver:
        command += ['--noserver']
    return command


def dump_websites_from_csv(ctx) -> list[(str, str)]:
    websites = []
    with open(ctx.input) as csvfile:
        reader = csv.reader(csvfile)
        for file in reader:
            # Used to skip empty lines, especially files with trailing new line
            # character
            if len(file) >= 1 and ctx.urlcol < len(file):
                # If file is not a csv, just output files to output dir
                url = file[ctx.urlcol]
                out = "" if len(file) == 1 else file[ctx.outcol]
                websites.append((url, out))
    return websites


def run_in_batches(ctx, executable_commands):
    with (concurrent.futures.ThreadPoolExecutor(max_workers=ctx.workers)
          as executor):
        lower_bound = 0
        # Slow start
        if ctx.type == 'mail' and not ctx.noserver and ctx.slowstart:
            while (get_cached_mx_count(ctx) < ctx.slowuntil and
                   lower_bound < ctx.shardsize):
                futures = [executor.submit(scan, (ctx.shardsize, task))
                           for task in executable_commands[
                               lower_bound:lower_bound + ctx.slowbatchsize
                               ]
                           ]
                concurrent.futures.wait(futures)
                lower_bound += ctx.slowbatchsize
            if get_cached_mx_count(ctx) >= ctx.slowuntil:
                ctx.slowstart = False
                print('Slow start completed!')

        if ctx.type == 'mail':
            # Disable caching mxs when not in slow start
            futures = [executor.submit(
                scan, (
                    ctx.shardsize,
                    task + ['--no-cache-mx']
                )
            ) for task in executable_commands[lower_bound:]]
            # Wait for all tasks to complete
            concurrent.futures.wait(futures)
        else:
            futures = [executor.submit(
                scan, (ctx.shardsize, task)
            ) for task in executable_commands]
            concurrent.futures.wait(futures)


def shard_tasks(tasks: list[list[str]], chunk_size: int):
    shards = []
    for i in range(math.ceil(len(tasks) / chunk_size)):
        shards.append(tasks[i * chunk_size:(i + 1) * chunk_size])
    return shards


def get_cached_mx_count(ctx):
    if not ctx.noserver:
        try:
            with urllib.request.urlopen(
                    (SERVER_URL + MX_COUNT_ENDPOINT).format(
                    port=os.environ.get("PORT", DEFAULT_PORT)
                    )
            ) as resp:
                if resp.status == 200:
                    num = int(resp.read())
                    return num
                else:
                    sys.exit(f'Unable to complete slow startup: '
                             f'Server returned status {resp.status} '
                             f'instead of 200')
        except Exception:
            if Exception is ValueError:
                sys.exit('Non-int cached mx count returned from server')
            else:
                sys.exit('Server is not running.')
    return 0


def start(ctx):
    if not ctx.noserver:
        try:
            print('Attempting to connect to ' +
                  SERVER_URL.format(port=os.environ.get("PORT", DEFAULT_PORT)))
            with urllib.request.urlopen(SERVER_URL.format(
                    port=os.environ.get("PORT", DEFAULT_PORT))) as resp:
                if resp.status != 200:
                    sys.exit(f'Server returned status '
                             f'{resp.status} instead of 200')
                print('Successfully connected!')
        except Exception:
            sys.exit('Server is not running.')

    num_cpu = multiprocessing.cpu_count()
    print(f'Using {num_cpu} CPU cores')
    print(f'Num workers: {ctx.workers}')
    # dump gov websites
    govwebsites = dump_websites_from_csv(ctx)

    commands = []
    time = datetime.now().strftime("%Y-%m-%d")
    for website, dir in govwebsites:
        commands.append(prepare_subcommand(ctx, time, website, dir))
    print(f'Number of commands to execute: {len(commands)}')
    if ctx.seed is not None:
        random.seed(ctx.seed)

    random.shuffle(commands)
    shards = shard_tasks(commands, ctx.shardsize)
    print(
        f'Number of shards (split into groups of size {ctx.shardsize}): '
        f'{len(shards)}'
    )

    if ctx.slowstart:
        print(
            f'Slow start detected. Conducting scans '
            f'in groups of size {ctx.slowbatchsize} '
            f'until {ctx.slowuntil} mx records are cached and locked in.'
        )

    for index, shard in enumerate(shards[ctx.batchstart:]):
        print(f'Running batch {index + ctx.batchstart}')
        run_in_batches(ctx, shard)
        print(f'Done with batch {index + ctx.batchstart}')


def main():
    parser = argparse.ArgumentParser(
        prog='ParallelScans',
        description='Conducts parallelized scans with the \'scan\' binary.' +
                    'Scans are output to a dated folder.')
    parser.add_argument(
        '-input',
        action='store',
        help="path to default file (default input/dataset.csv)",
        default='input/dataset.csv',
        required=True)
    parser.add_argument('-output', action='store',
                        help="path to output directory", required=True)
    parser.add_argument(
        '-type',
        action='store',
        help="type of query: (tls, mail, dns)",
        choices=[
            'tls',
            'mail',
            'dns'],
        required=True)
    parser.add_argument(
        '-shardsize',
        action='store',
        help="size of scan batches (default 50000)",
        default=50000,
        type=int,
        required=False)
    parser.add_argument(
        '-batchstart',
        action='store',
        help="batch number to begin scans (default 0)",
        default=0,
        type=int,
        required=False)
    parser.add_argument(
        '-seed',
        action='store',
        help="seed order of scans",
        type=int,
        required=False)
    parser.add_argument(
        '-workers',
        action='store',
        help="increase for greater performance (default 400)",
        default=400,
        type=int,
        required=False)
    parser.add_argument(
        '-urlcol',
        action='store',
        help="column index to read urls from",
        default=0,
        type=int,
        required=False)
    parser.add_argument(
        '-outcol',
        action='store',
        help="column index to read output folders from",
        default=1,
        type=int,
        required=False)
    parser.add_argument(
        '-querytype',
        action='store',
        help="query type for dns type scans (A, MX, NS, etc.): default A",
        default="A",
        choices=QUERY_TYPES)
    parser.add_argument(
        '-binstore',
        action='store',
        help="location containing the scan binary",
        default="bin/",
        required=False)
    parser.add_argument(
        '-nodate',
        action='store_true',
        help="if date should be included in result directory",
        default=False,
        required=False)
    parser.add_argument(
        '-noserver',
        action='store_true',
        help="if server should be used in scans",
        default=False,
        required=False)
    parser.add_argument(
        '-slowstart',
        action='store_true',
        help="slow start when caching mx's",
        default=False,
        required=False
    )
    parser.add_argument(
        '-slowuntil',
        action='store',
        help="slow start until specified number of mxs are cached (locked in)",
        default=20,
        type=int,
        required=False
    )
    parser.add_argument(
        '-slowbatchsize',
        action='store',
        help="batch sizes when in slow start",
        default=20,
        type=int,
        required=False
    )
    args = parser.parse_args()
    start(args)


if __name__ == "__main__":
    main()
