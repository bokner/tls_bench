-module(ssl_client).

-include("tls_bench.hrl").

-export([benchmark/5]).

-define(SENT_BYTE, 2).

-ifdef(check_data_valid).
check(Data) ->
    Data = <<?SENT_BYTE:(byte_size(Data))/little-signed-integer-unit:8>>,
    ok.
-define(CHECK_DATA(Data), check(Data)).
-else.
-define(CHECK_DATA(Data), ok).
-endif.

benchmark(ClientMod, Port, ConcurrentConnections, Requests, MessageLength) ->
    code_loader:start(),
    {ok, _} = application:ensure_all_started(tls_bench),

    {ok, ClientOpt} = tlsb_utils:env(client),
    Host = tlsb_utils:lookup(host, ClientOpt),
    ConnectTimeout = tlsb_utils:lookup(connect_timeout, ClientOpt),
    RecvTimeout = tlsb_utils:lookup(recv_timeout, ClientOpt),
    Opts = impl_opts(ClientMod, ClientOpt),
    ServerTag = tlsb_config:get_server_by_port(Port),

    ReqPerConnection = round(Requests/ ConcurrentConnections),
    Message = <<?SENT_BYTE:MessageLength/little-signed-integer-unit:8>>,
    SeqPerClient = lists:seq(1, ReqPerConnection),

    ?INFO_MSG("## start testing on ~p:~p, server stack: ~p, client stack: ~p", [Host, Port, ServerTag, ClientMod]),
    ?INFO_MSG("## requests per connection: ~p msg length: ~s total requests: ~p concurrency level: ~p", [
        ReqPerConnection,
        tlsb_utils:format_size(MessageLength),
        Requests,
        ConcurrentConnections]),
    ClientFun = fun() ->
        {ok, Socket} = essl:connect(ClientMod, Host, Port, Opts, ConnectTimeout),

        SendFun = fun(_) ->
            ok = essl:send(Socket, Message)
        end,

        spawn(fun() -> lists:foreach(SendFun, SeqPerClient) end),

        case recv(Socket, ReqPerConnection*MessageLength, RecvTimeout) of
            ok ->
                essl:close(Socket);
            _ ->
                ok
        end
    end,

    {Ts, _} = timer:tc(fun() -> multi_spawn:do_work(ClientFun, ConcurrentConnections) end),

    TsMs = Ts/1000,
    TsSec = erlang:max(1, TsMs/1000),

    BandwidthSize = 2*MessageLength*Requests,
    BytesPerSec = BandwidthSize/TsSec,

    ?INFO_MSG("################################################", []),
    ?INFO_MSG("## completed in :~p ms", [TsMs]),
    ?INFO_MSG("## bandwidth throughput: ~s/s", [tlsb_utils:format_size(BytesPerSec)]),
    ?INFO_MSG("################################################", []).

recv(_Socket, Bytes, _Timeout) when Bytes =< 0 ->
    case Bytes < 0 of
        true ->
            ?ERROR_MSG("unexpected number of bytes received", []);
        _ ->
            ok
    end;
recv(Socket, Bytes, Timeout) ->
    case essl:recv(Socket, Timeout) of
        {essl, Socket, Data} ->
            ok = ?CHECK_DATA(Data),
            recv(Socket, Bytes - byte_size(Data), Timeout);
        {essl_closed, Socket} ->
            closed;
        Error ->
            ?ERROR_MSG("Client received unexpected msg: ~p",[Error]),
            {error, Error}
    end.

impl_opts(gen_tcp, ClientOpt) ->
    tlsb_utils:lookup(tcp_opt, ClientOpt);

impl_opts(ssl, ClientOpt) ->
    TcpOpts = tlsb_utils:lookup(tcp_opt, ClientOpt),
    TlsOpts = tlsb_config:get_tls_opt(ssl, ClientOpt),
    TcpOpts ++ TlsOpts.
