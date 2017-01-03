-module(tls_bench_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-include("tls_bench.hrl"). 

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Children = ranch_listeners(),
    {ok, { {one_for_one, 5, 10}, Children} }.

ranch_sup() ->
    {ranch_sup, {ranch_sup, start_link, []},
     permanent, 5000, supervisor, [ranch_sup]}.

ranch_listeners() ->
    {ok, ServersConf} = application:get_env(tls_bench, servers),
    {ok, RunningServers} = application:get_env(tls_bench, impls),
    ListenOpts = tlsb_utils:lookup(listen_opt, ServersConf),
    Acceptors = tlsb_utils:lookup(acceptors, ServersConf),
    lists:map(fun(Impl) ->
        ImplConfig = tlsb_utils:lookup(Impl, ServersConf),
        Port = tlsb_utils:lookup(port, ImplConfig),
	ChildName = atom_to_list(Impl) ++ "_bench",
        start_app(Impl),
        ImplOpts = impl_opts(Impl, ImplConfig, ServersConf),
        print_opts(Impl, ListenOpts, Acceptors, Port, ImplOpts),
	ranch:child_spec(ChildName, Acceptors, ranch_essl,
                [
		 {impl, Impl}, {port, Port},
		 {max_connections, infinity}
		 | ListenOpts ++ ImplOpts
		],
                ranch_essl_server, [])
	end, RunningServers).

impl_opts(gen_tcp, _ImplConfig, _SharedConfig) ->
  [];

impl_opts(SSL_Mod, ImplConfig, SharedConfig) when SSL_Mod == ?MOD_ETLS 
	orelse SSL_Mod == ?MOD_SSL 
	orelse SSL_Mod == ?MOD_ERLTLS -> 
  TLSOpts = tlsb_utils:lookup(tls_opt, SharedConfig),
  ImplConfig ++ TLSOpts;

impl_opts(P1_Mod, ImplConfig, SharedConfig) 
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  TLSOpts = tlsb_utils:lookup(tls_opt, SharedConfig),
  [{tls_opt, TLSOpts ++ ImplConfig}].

start_app(?MOD_TCP) -> ok;
start_app(?MOD_SSL) -> application:ensure_all_started(ssl);
start_app(?MOD_ETLS) -> application:ensure_all_started(etls);
start_app(?MOD_ERLTLS) -> application:ensure_all_started(erltls);
start_app(P1_Mod) when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS -> 
  application:ensure_all_started(P1_Mod).

print_opts(Impl, ListenOpts, Acceptors, Port, ImplOpts) ->
    ?INFO_MSG("~p start listening on port ~p with ~p acceptors", [Impl, Port, Acceptors]),
    ?INFO_MSG("~p listen opt: ~200p", [Impl, ListenOpts]),
    ?INFO_MSG("~p tls options: ~200p", [Impl, ImplOpts]).

