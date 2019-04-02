"""
uftrace helper script for use jaeger.

Reference: https://www.jaegertracing.io/
Requirement : jaeger_client python library

"""

import logging
import time
from jaeger_client import Config

app_name = "uftrace_jaeger_"
tracer = None
queue = []

def init_tracer(service_name='your-app-name'):
    global tracer

    if (tracer is not None):
        return tracer

    log_level = logging.DEBUG
    logging.getLogger('').handlers = []
    logging.basicConfig(format='%(asctime)s %(message)s', level=log_level)

    config = Config(
        config={
            'sampler': {
                'type': 'const',
                'param': 1,
            },
            'logging': True,
        },
        service_name = service_name,
        validate=True,
    )
    # this call also sets opentracing.tracer
    tracer = config.initialize_tracer()
    return tracer

def uftrace_begin(ctx):
    print("[BEGIN]")
    global app_name
    if "cmds" in ctx:
        cmd = "".join(ctx["cmds"])
        print("APPNAME : " + cmd)
        app_name += cmd

    init_tracer(service_name=app_name)

def uftrace_entry(ctx):
    global tracer
    global queue

    parent = None
    if (len(queue) > 0):
        parent = queue[-1]

    if (parent is None):
        with tracer.start_span(ctx["name"]) as span:
            span.log_kv({'event' : 'entry'})
    else:
        with tracer.start_span(ctx["name"],child_of=parent) as span:
            span.log_kv({'event' : 'entry'})

    queue.append(span)

def uftrace_exit(ctx):
    global tracer
    global queue

    if (len(queue) > 0):
        span = queue.pop()
        span.finish()

def uftrace_end():
    global tracer
    time.sleep(2)
    tracer.close()
