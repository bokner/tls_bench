-module(ranch_essl_server).
-behaviour(gen_server).
-behaviour(ranch_protocol).

%% API.
-export([start_link/4]).

%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-define(TIMEOUT, 30000).

-record(state, {socket, msg_count=0, total_size = 0}).
-include("tls_bench.hrl").
%% API.

start_link(Ref, Socket, Transport, Opts) ->
	{ok, proc_lib:spawn_link(?MODULE, init, [{Ref, Socket, Transport, Opts}])}.

%% gen_server.

%% This function is never called. We only define it so that
%% we can use the -behaviour(gen_server) attribute.
%init([]) -> {ok, undefined}.

init({Ref, _Socket, Transport, _Opts = []}) ->
	{ok, Socket1} = ranch:accept_ack(Ref),
	ok = Transport:setopts(Socket1, [{active, once}]),
	gen_server:enter_loop(?MODULE, [],
		#state{socket=Socket1},
		?TIMEOUT).

handle_info({_Transport, _ImplSocket, Data}, #state{
	socket = Socket, msg_count = Count, total_size = Total} = State) when byte_size(Data) > 1 ->
	ranch_essl:setopts(Socket, [{active, once}]),
        {NewCount, NewTotal} = case read_data(Socket, Data) of
	   <<>> ->
		{Count, Total};
           D -> 
		ranch_essl:send(Socket, D),
		{Count + 1, Total + byte_size(D)} 
        end,
	{noreply, State#state{msg_count = NewCount, total_size = NewTotal}, ?TIMEOUT};
handle_info({tcp_closed, _Socket}, State) ->
	{stop, normal, State};
handle_info({tcp_error, _, Reason}, State) ->
	{stop, Reason, State};
handle_info(timeout, State) ->
	{stop, normal, State};
handle_info(_Info, State) ->
	{stop, normal, State}.

handle_call(_Request, _From, State) ->
	{reply, ok, State}.

handle_cast(_Msg, State) ->
	{noreply, State}.

terminate(Reason, #state{msg_count = Count, total_size = Total, socket = Socket} = _State) ->
   ?INFO_MSG("The connection ~p closed with '~p', received ~p messages, total size is ~p", [erlang:phash2(Socket), Reason, Count, Total]),
	ok.

code_change(_OldVsn, State, _Extra) ->
	{ok, State}.


read_data(#essl_socket{socket = TlsSocket, mod = P1_Mod} = _Socket, TlsData) 
    when P1_Mod == ?MOD_FAST_TLS orelse P1_Mod == ?MOD_P1_TLS ->
    {ok, Data} = P1_Mod:recv_data(TlsSocket, TlsData),
    Data;
read_data(_Socket, Data) ->
    Data.

