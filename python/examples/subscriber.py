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
"""EII Message Bus subscriber example
"""

import time
import json
import argparse
import eii.msgbus as mb

# Argument parsing
ap = argparse.ArgumentParser()
ap.add_argument('config', help='JSON configuration')
ap.add_argument('-t', '--topic', default='publish_test', help='Topic')
ap.add_argument('-np', '--no-print', dest='no_print', default=False,
                action='store_true', help='Do not print JSON message')
ap.add_argument('-pb', '--print-blob', dest='print_blob', default=False,
                action='store_true', help='Print blobs, if they exist')
args = ap.parse_args()

msgbus = None
subscriber = None

with open(args.config, 'r') as f:
    config = json.load(f)

try:
    print('[INFO] Initializing message bus context')
    msgbus = mb.MsgbusContext(config)

    print(f'[INFO] Initializing subscriber for topic \'{args.topic}\'')
    subscriber = msgbus.new_subscriber(args.topic)

    print('[INFO] Running...')
    while True:
        msg = subscriber.recv()

        print(f'[INFO] Received message on topic: {msg.get_name()}')
        if not args.no_print:
            print(f'JSON Data: {msg.get_meta_data()}')

        if args.print_blob:
            blobs = msg.get_blob()
            if blobs is not None:
                if isinstance(blobs, bytes):
                    blobs = [blobs]
                for i, blob in enumerate(blobs):
                    print(f'BLOB {i}:\n{blob}')
            else:
                print('NO BLOBS')
except KeyboardInterrupt:
    print('[INFO] Quitting...')
finally:
    if subscriber is not None:
        subscriber.close()
