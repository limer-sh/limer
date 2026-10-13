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

    srv = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pb2_grpc.add_EchoServicer_to_server(Echo(), srv)
    srv.add_insecure_port(f"127.0.0.1:{port}")
    srv.start()
    srv.wait_for_termination()


def call(target, tls=None, sni=None, stream=0, expect_name=None, fail=False):
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
            else:
                i += 1
        sys.exit(call(target, **kw))
