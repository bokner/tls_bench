-module(ranch_essl).
-author("silviu.caragea").

-include("tls_bench.hrl").

%% Ranch callbacks
-export([name/0]).
-export([secure/0]).
-export([messages/0]).
-export([listen/1]).
-export([disallowed_listen_options/0]).
-export([accept/2]).
-export([accept_ack/2]).
-export([connect/3]).
-export([connect/4]).
-export([recv/3]).
-export([send/2]).
-export([setopts/2]).
-export([controlling_process/2]).
-export([peername/1]).
-export([sockname/1]).
-export([shutdown/2]).
-export([close/1]).

%% Utility functions
-export([connect/5]).



name() -> essl.
secure() -> true.
messages() -> {essl, essl_closed, essl_error}.
disallowed_listen_options() -> [].


connect(Host, Port, Options) ->
  connect(Host, Port, Options, infinity).


connect(Host, Port, Options, Timeout) ->
    Mod = tlsb_utils:lookup(impl, Options), 
    TransportOpts = lists:keydelete(impl, 1, Options),
    case connect(Mod, Host, Port, TransportOpts, Timeout) of
      {ok, Socket} -> {ok, #essl_socket{socket = Socket, mod = Mod, options = TransportOpts}};
      Error -> Error
    end.

connect(?MOD_ETLS, Host, Port, Options, Timeout) ->
    ranch_etls:connect(Host, Port, Options, Timeout);

connect(P1_Mod, Host, Port, Options, Timeout) when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
            {ok, TcpSocket} = ranch_tcp:connect(Host, Port, lists:keydelete(tls_opt, 1, Options), Timeout),
            TlsOpts = tlsb_utils:lookup(tls_opt, Options),
            {ok, _TlsSocket} = P1_Mod:tcp_to_tls(TcpSocket, [connect|TlsOpts]);

connect(?MOD_SSL, Host, Port, Options, Timeout) ->
            ranch_ssl:connect(Host, Port, Options, Timeout);

connect(?MOD_ERLTLS, Host, Port, Options, Timeout) ->
            ranch_erltls:connect(Host, Port, Options, Timeout);

connect(?MOD_TCP, Host, Port, Options, Timeout) ->
            ranch_tcp:connect(Host, Port, Options, Timeout).


listen(Options) ->
  Mod = tlsb_utils:lookup(impl, Options),
  TransportOpts = lists:keydelete(impl, 1, Options),
  case listen(Mod, TransportOpts) of
    {ok, Socket} -> {ok, #essl_socket{socket = Socket, mod = Mod, options = TransportOpts}};
    Error -> Error
  end.

listen(?MOD_ETLS, Options) ->
    ranch_etls:listen(Options);

listen(?MOD_SSL, Options) ->
    ranch_ssl:listen(Options);


listen(P1_Mod, Options) when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  ranch_tcp:listen(lists:keydelete(tls_opt, 1, Options));

listen(?MOD_SSL, Options) ->
  ranch_ssl:listen(Options);

listen(?MOD_ERLTLS, Options) ->
  ranch_erltls:listen(Options);

listen(?MOD_TCP, Options) ->
    ranch_tcp:listen(Options).

accept(LSocket, Timeout) ->
  case accept1(LSocket, Timeout) of
    {ok, Socket} -> {ok, LSocket#essl_socket{socket = Socket}};
    Error -> Error
  end.

accept1(#essl_socket{socket = LSocket, mod = ?MOD_ETLS}, Timeout) ->
    ranch_etls:accept(LSocket, Timeout);

accept1(#essl_socket{socket = LSocket, mod = ?MOD_SSL}, Timeout) ->
    ranch_ssl:accept(LSocket, Timeout);

accept1(#essl_socket{socket = LSocket, mod = ?MOD_ERLTLS}, Timeout) ->
    ranch_erltls:accept(LSocket, Timeout);

accept1(#essl_socket{socket = LSocket, mod = P1_Mod, options = Options}, Timeout)
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  case gen_tcp:accept(LSocket, Timeout) of
    {ok, TCPSocket} -> P1_Mod:tcp_to_tls(TCPSocket, tlsb_utils:lookup(tls_opt, Options));
    Error -> Error
  end; 

accept1(#essl_socket{socket = LSocket, mod = ?MOD_TCP}, Timeout) ->
    ranch_tcp:accept(LSocket, Timeout).

accept_ack(Socket, Timeout) ->
  case accept_ack1(Socket, Timeout) of
    ok -> {ok, Socket};
    {ok, UpgradedSocket} when is_record(UpgradedSocket, essl_socket) ->
      {ok, UpgradedSocket};
    {ok, UpgradedSocket} ->
      {ok, Socket#essl_socket{socket = UpgradedSocket}};
    Error
      -> Error
  end.

accept_ack1(#essl_socket{socket = LSocket, mod = ?MOD_ETLS}, Timeout) ->
    ok = ranch_etls:accept_ack(LSocket, Timeout);

accept_ack1(#essl_socket{socket = LSocket, mod = ?MOD_SSL}, Timeout) ->
    ok = ranch_ssl:accept_ack(LSocket, Timeout);

accept_ack1(#essl_socket{socket = LSocket, mod = ?MOD_ERLTLS}, Timeout) ->
    ok = ranch_erltls:accept_ack(LSocket, Timeout);

accept_ack1(#essl_socket{socket = LSocket, mod = P1_Mod}, Timeout)
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
    ok = ranch_tcp:accept_ack(LSocket, Timeout);

accept_ack1(#essl_socket{socket = LSocket, mod = ?MOD_TCP}, Timeout) ->
    ok = ranch_tcp:accept_ack(LSocket, Timeout).


peername(#essl_socket{socket = LSocket, mod = ?MOD_ETLS}) ->
  ranch_etls:peername(LSocket);

peername(#essl_socket{socket = LSocket, mod = ?MOD_SSL}) ->
  ranch_ssl:peername(LSocket);

peername(#essl_socket{socket = LSocket, mod = ?MOD_ERLTLS}) ->
  ranch_erltls:peername(LSocket);

peername(#essl_socket{socket = LSocket, mod = P1_Mod})
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  ranch_tcp:peername(LSocket#tlssock.tcpsock);

peername(#essl_socket{socket = LSocket, mod = ?MOD_TCP}) ->
  ranch_tcp:peername(LSocket).


sockname(#essl_socket{socket = LSocket, mod = ?MOD_ETLS}) ->
  ranch_etls:sockname(LSocket);

sockname(#essl_socket{socket = LSocket, mod = ?MOD_SSL}) ->
  ranch_ssl:sockname(LSocket);

sockname(#essl_socket{socket = LSocket, mod = ?MOD_ERLTLS}) ->
  ranch_erltls:sockname(LSocket);

sockname(#essl_socket{socket = LSocket, mod = P1_Mod})
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  ranch_tcp:sockname(LSocket);

sockname(#essl_socket{socket = LSocket, mod = ?MOD_TCP}) ->
  ranch_tcp:sockname(LSocket).

shutdown(#essl_socket{socket = LSocket, mod = ?MOD_ETLS}, Type) ->
  ranch_etls:shutdown(LSocket, Type);

shutdown(#essl_socket{socket = LSocket, mod = ?MOD_SSL}, Type) ->
  ranch_ssl:shutdown(LSocket, Type);

shutdown(#essl_socket{socket = LSocket, mod = ?MOD_ERLTLS}, Type) ->
  ranch_erltls:shutdown(LSocket, Type);

shutdown(#essl_socket{socket = LSocket, mod = P1_Mod}, Type)
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  ranch_tcp:shutdown(LSocket#tlssock.tcpsock, Type);

shutdown(#essl_socket{socket = LSocket, mod = ?MOD_TCP}, Type) ->
  ranch_tcp:shutdown(LSocket, Type).


setopts(#essl_socket{socket = LSocket, mod = ?MOD_ETLS}, Options) ->
  ranch_etls:setopts(LSocket, Options);

setopts(#essl_socket{socket = LSocket, mod = ?MOD_SSL}, Options) ->
  ranch_ssl:setopts(LSocket, Options);

setopts(#essl_socket{socket = LSocket, mod = ?MOD_ERLTLS}, Options) ->
  ranch_erltls:setopts(LSocket, Options);

setopts(#essl_socket{socket = LSocket, mod = P1_Mod}, Options)
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  %%TCPSock = get_tcpsock(LSocket),
  P1_Mod:setopts(LSocket, Options);

setopts(#essl_socket{socket = LSocket, mod = ?MOD_TCP}, Options) ->
  ranch_tcp:setopts(LSocket, Options).

controlling_process(#essl_socket{socket = LSocket, mod = ?MOD_ETLS}, Pid) ->
  ranch_etls:controlling_process(LSocket, Pid);

controlling_process(#essl_socket{socket = LSocket, mod = ?MOD_SSL}, Pid) ->
  ranch_ssl:controlling_process(LSocket, Pid);

controlling_process(#essl_socket{socket = LSocket, mod = ?MOD_ERLTLS}, Pid) ->
  ranch_erltls:controlling_process(LSocket, Pid);

controlling_process(#essl_socket{socket = LSocket, mod = P1_Mod}, Pid)
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  P1_Mod:controlling_process(LSocket, Pid);

controlling_process(#essl_socket{socket = LSocket, mod = ?MOD_TCP}, Pid) ->
  ranch_tcp:controlling_process(LSocket, Pid).


send(#essl_socket{socket = LSocket, mod = ?MOD_ETLS}, Data) ->
  ranch_etls:send(LSocket, Data);

send(#essl_socket{socket = LSocket, mod = ?MOD_SSL}, Data) ->
  ranch_ssl:send(LSocket, Data);

send(#essl_socket{socket = LSocket, mod = ?MOD_ERLTLS}, Data) ->
  ranch_erltls:send(LSocket, Data);

send(#essl_socket{socket = LSocket, mod = P1_Mod}, Data) 
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  P1_Mod:send(LSocket, Data);

send(#essl_socket{socket = LSocket, mod = ?MOD_TCP}, Data) ->
  ranch_tcp:send(LSocket, Data).

recv(#essl_socket{socket = LSocket, mod = ?MOD_ETLS}, Size, Timeout) ->
  ranch_etls:recv(LSocket, Size, Timeout);

recv(#essl_socket{socket = LSocket, mod = ?MOD_SSL}, Size, Timeout) ->
  ranch_ssl:recv(LSocket, Size, Timeout);

recv(#essl_socket{socket = LSocket, mod = ?MOD_ERLTLS}, Size, Timeout) ->
  ranch_erltls:recv(LSocket, Size, Timeout);

recv(#essl_socket{socket = LSocket, mod = P1_Mod}, Size, Timeout) 
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  P1_Mod:recv(LSocket, Size, Timeout);

recv(#essl_socket{socket = LSocket, mod = ?MOD_TCP}, Size, Timeout) ->
  ranch_tcp:recv(LSocket, Size, Timeout).

close(#essl_socket{socket = Socket, mod = ?MOD_ETLS}) ->
  ranch_etls:close(Socket);

close(#essl_socket{socket = Socket, mod = P1_Mod})
  when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
  ranch_tcp:close(Socket#tlssock.tcpsock);

close(#essl_socket{socket = Socket, mod = ?MOD_SSL}) ->
  ranch_ssl:close(Socket);

close(#essl_socket{socket = Socket, mod = ?MOD_ERLTLS}) ->
  ranch_erltls:close(Socket);

close(#essl_socket{socket = Socket, mod = ?MOD_TCP}) ->
  ranch_tcp:close(Socket).


