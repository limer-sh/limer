#!/usr/bin/env python3
"""Tiny gRPC service used to test HTTP/2 passthrough (unary + server streaming).

    python3 tests/grpc_service.py serve PORT NAME
    python3 tests/grpc_service.py call  HOST:PORT [--tls CERT --sni NAME] [--stream N] [--expect-name NAME]

The proto is compiled on the fly with grpcio-tools, so no generated files
are checked in.
"""
import os
import sys
import tempfile
import importlib

PROTO = """
syntax = "proto3";
package limertest;
service Echo {
  rpc Ping (Req) returns (Resp);
  rpc Count (Req) returns (stream Resp);
  rpc Fail (Req) returns (Resp);
  rpc Chat (stream Req) returns (stream Resp);
  rpc Sum (stream Req) returns (Resp);
}
message Req { string text = 1; int32 n = 2; }
message Resp { string text = 1; string server = 2; int32 i = 3; }
"""


def build():
    from grpc_tools import protoc
    d = tempfile.mkdtemp(prefix="limer-grpc-")
    with open(os.path.join(d, "limertest.proto"), "w") as f:
        f.write(PROTO)
    rc = protoc.main(["protoc", f"-I{d}", f"--python_out={d}", f"--grpc_python_out={d}", os.path.join(d, "limertest.proto")])
    if rc != 0:
        raise SystemExit("protoc failed")
    sys.path.insert(0, d)
    pb2 = importlib.import_module("limertest_pb2")
    pb2_grpc = importlib.import_module("limertest_pb2_grpc")
    return pb2, pb2_grpc


def serve(port, name):
    import grpc
    from concurrent import futures
    pb2, pb2_grpc = build()

    class Echo(pb2_grpc.EchoServicer):
        def Ping(self, req, ctx):
            md = dict(ctx.invocation_metadata())
            ctx.set_trailing_metadata((("x-server", name),))
            return pb2.Resp(text=f"pong:{req.text}:xff={md.get('x-forwarded-for','')}", server=name, i=req.n)

        def Count(self, req, ctx):
            for i in range(req.n):
                yield pb2.Resp(text=f"tick {i}", server=name, i=i)

        def Fail(self, req, ctx):
            ctx.abort(grpc.StatusCode.FAILED_PRECONDITION, f"nope from {name}")

        def Chat(self, reqs, ctx):
            # bidirectional: answer every message as it arrives
            for i, r in enumerate(reqs):
                yield pb2.Resp(text=f"echo:{r.text}", server=name, i=i)

        def Sum(self, reqs, ctx):
            total = 0
            n = 0
            for r in reqs:
                total += r.n
                n += 1
            return pb2.Resp(text=f"sum:{total}", server=name, i=n)

    srv = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pb2_grpc.add_EchoServicer_to_server(Echo(), srv)
    srv.add_insecure_port(f"127.0.0.1:{port}")
    srv.start()
    srv.wait_for_termination()


def call(target, tls=None, sni=None, stream=0, expect_name=None, fail=False, chat=0, sum_n=0):
    import grpc
    pb2, pb2_grpc = build()
    opts = []
    if sni:
        opts.append(("grpc.ssl_target_name_override", sni))
    if tls:
        creds = grpc.ssl_channel_credentials(root_certificates=open(tls, "rb").read())
        ch = grpc.secure_channel(target, creds, options=opts)
    else:
        ch = grpc.insecure_channel(target, options=opts)
    stub = pb2_grpc.EchoStub(ch)
    if fail:
        try:
            stub.Fail(pb2.Req(text="x"), timeout=5)
            print("unexpected success")
            return 1
        except grpc.RpcError as e:
            print(f"error {e.code().name}: {e.details()}")
            return 0
    if chat:
        import queue, threading
        q = queue.Queue()

        def gen():
            while True:
                item = q.get()
                if item is None:
                    return
                yield item
        replies = stub.Chat(gen(), timeout=20)
        got = []
        # true ping-pong: each reply must come back before the next message is sent
        for i in range(chat):
            q.put(pb2.Req(text=f"m{i}", n=i))
            got.append(next(replies).text)
        q.put(None)
        rest = [r.text for r in replies]
        print(f"chat {len(got)} replies, last={got[-1] if got else None}, extra={len(rest)}")
        return 0 if len(got) == chat and got[-1] == f"echo:m{chat-1}" and not rest else 1
    if sum_n:
        resp = stub.Sum(iter(pb2.Req(text="x", n=i) for i in range(sum_n)), timeout=20)
        print(f"{resp.text} count={resp.i} server={resp.server}")
        return 0 if resp.i == sum_n else 1
    if stream:
        got = [r.text for r in stub.Count(pb2.Req(text="s", n=stream), timeout=10)]
        print(f"streamed {len(got)} messages, last={got[-1] if got else None}")
        return 0 if len(got) == stream else 1
    resp, callr = stub.Ping.with_call(pb2.Req(text="hello", n=7), timeout=5)
    trailers = dict(callr.trailing_metadata())
    print(f"{resp.text} server={resp.server} i={resp.i} trailer-x-server={trailers.get('x-server')}")
    if expect_name and resp.server != expect_name:
        return 1
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[0] == "serve":
        serve(int(a[1]), a[2])
    else:
        target = a[1]
        kw = {}
        i = 2
        while i < len(a):
            if a[i] == "--tls":
                kw["tls"] = a[i + 1]; i += 2
            elif a[i] == "--sni":
                kw["sni"] = a[i + 1]; i += 2
            elif a[i] == "--stream":
                kw["stream"] = int(a[i + 1]); i += 2
            elif a[i] == "--expect-name":
                kw["expect_name"] = a[i + 1]; i += 2
            elif a[i] == "--fail":
                kw["fail"] = True; i += 1
            elif a[i] == "--chat":
                kw["chat"] = int(a[i + 1]); i += 2
            elif a[i] == "--sum":
                kw["sum_n"] = int(a[i + 1]); i += 2
            else:
                i += 1
        sys.exit(call(target, **kw))
