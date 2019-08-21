# Copyright (c) 2019 Intel Corporation.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""Benchmarking script for testing the Python binding for the EIS
Message Bus.
"""

import json
import time
import argparse
import os
from statistics import mean
import eis.msgbus as msgbus


# Globals
TOPIC = 'benchmarking'


def parse_args():
    """Parse command line arguments.
    """
    ap = argparse.ArgumentParser()
    ap.add_argument('msgbus_config', help='Msgbus JSON configuration')
    sp = ap.add_subparsers()

    ap_pub = sp.add_parser('publish', help='Run publisher side of the script')
    ap_pub.add_argument('size', type=int, help='Size of payload')
    ap_pub.add_argument('measurement', choices=('Kib', 'Mib',),
                    help='Measurement of the size')
    ap_pub.set_defaults(func=run_publisher)

    ap_sub = sp.add_parser(
            'subscribe', help='Run subscriber side of the script')
    ap_sub.set_defaults(func=run_subscriber)

    ap.add_argument('num_msgs', type=int, help='Number of publications')

    return ap.parse_args()


def run_publisher(ctx, args):
    """Run publisher end of benchmarking.
    """
    print('[INFO] Initializing publisher')
    publisher = ctx.new_publisher(TOPIC)

    print('[INFO] Creating data blob')
    if args.measurement == 'Kib':
        blob = b'\x01' * 1024 * args.size
    else:
        assert args.measurement == 'Mib'
        blob = b'\x01' * 1024 * 1024 * args.size

    try:
        start = time.time()

        print('[INFO] Running as publisher')
        for i in range(args.num_msgs):
            ts = time.time()
            publisher.publish(({'ts': ts}, blob,))

        elapsed = time.time() - start
        print((f'[INFO] Finished - elapsed {elapsed}s, '
               f'MPS {args.num_msgs / elapsed}'))
        time.sleep(60)
    finally:
        publisher.close()

def run_subscriber(ctx, args):
    """Run subscriber end of benchmarking.
    """
    print('[INFO] Initializing subscriber')
    subscriber = ctx.new_subscriber(TOPIC)

    timestamps = []
    count = 0
    start = None

    try:
        print('[INFO] Subscriber running')
        while count < args.num_msgs:
            msg, blob = subscriber.recv()
            ts = time.time()
            timestamps.append((ts, msg['ts'],))
            if start is None:
                start = ts
            count += 1
    except KeyboardInterrupt:
        print('[INFO] Interrupted')
    finally:
        print('[INFO] Calculating results')
        if len(timestamps) > 0:
            elapsed = time.time() - start
            times = list(map(lambda t: t[0] - t[1], timestamps))
            print(f'\tNUM: {len(timestamps)}')
            print(f'\tAVG: {mean(times)}')
            print(f'\tMIN: {min(times)}')
            print(f'\tMAX: {max(times)}')
            print(f'\tMPS: {count / elapsed}')
        subscriber.close()


def main():
    """Main method
    """
    args = parse_args()

    # Make sure that the ./.socks directory exist just in case this is using
    # IPC communication
    if not os.path.exists('./.socks'):
        os.mkdir('./.socks')

    with open(args.msgbus_config, 'r') as f:
        config = json.load(f)

    print('[INFO] Initializing message bus context')
    ctx = msgbus.MsgbusContext(config)

    # Start the benchmarking end specified by the CLI
    args.func(ctx, args)


if __name__ == '__main__':
    main()
