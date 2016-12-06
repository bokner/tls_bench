-module(tls_bench_app).

-behaviour(application).

-include("tls_bench.hrl").

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    tls_bench_sup:start_link().

stop(_State) ->
    ok.
