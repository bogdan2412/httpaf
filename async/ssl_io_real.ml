module Buffer_ = Buffer
open Core
open Async
open Async_ssl
module Buffer = Buffer_

module Unix = Core.Unix


let readf ssl_reader =
  fun _fd buffer ->
  Buffer.put_async buffer ~f:(fun bigstring ~off ~len ->
    let bigsubstr = Bigsubstring.create ~pos:off ~len bigstring in
    Reader.read_bigsubstring ssl_reader bigsubstr >>| function
      | `Eof -> 0
      | `Ok n -> n)
  >>| function
  | 0 -> `Eof
  | n -> `Ok n

let writev ssl_writer _fd =
  fun iovecs ->
    let iovecs_q = Queue.create ~capacity:(List.length iovecs) () in
    let len = List.fold ~init:0 ~f:(fun acc { Faraday.buffer; off = pos; len } ->
      Queue.enqueue iovecs_q (Unix.IOVec.of_bigstring ~pos ~len buffer);
      acc + len) iovecs
    in
    Writer.schedule_iovecs ssl_writer iovecs_q;
    Writer.flushed ssl_writer
    >>| fun () -> `Ok len

let close_read ssl_reader = fun _socket ->
  Reader.close ssl_reader

let close_write ssl_writer = fun _socket ->
  Writer.close ssl_writer

type client = Reader.t * Writer.t
type server = Reader.t * Writer.t

let reader (r, _) = r
let writer (_, w) = w

(* taken from https://github.com/janestreet/async_extra/blob/master/src/tcp.ml *)
let reader_writer_of_sock ?buffer_age_limit ?reader_buffer_size ?writer_buffer_size s =
  let fd = Socket.fd s in
  ( Reader.create ?buf_len:reader_buffer_size fd
  , Writer.create ?buffer_age_limit ?buf_len:writer_buffer_size fd )

let teardown_connection r w =
  Writer.close ~force_close:(Clock.after (sec 30.)) w >>= fun () ->
  Reader.close r

(* One needs to be careful around Async Readers and Writers that share the same underyling
   file descriptor, which is something that happens when they're used for sockets.

   Closing the Reader before the Writer will cause the Writer to throw and complain about
   its underlying file descriptor being closed. This is why instead of using Reader.pipe
   directly below, we write out an equivalent version which will first close the Writer
   before closing the Reader once the input pipe is fully consumed.

   Additionally, [Writer.pipe] will not close the writer if the pipe is closed, so in
   order to avoid leaking file descriptors, we allow the pipe 30 seconds to flush before
   closing the writer. *)
let reader_writer_pipes r w =
  let reader_pipe_r, reader_pipe_w = Pipe.create () in
  let writer_pipe = Writer.pipe w in
  upon (Reader.transfer r reader_pipe_w) (fun () ->
    teardown_connection r w >>> fun () ->
    Pipe.close reader_pipe_w);
  upon (Pipe.closed writer_pipe) (fun () ->
    Deferred.choose
      [ Deferred.choice (Clock.after (sec 30.))
          (fun () -> ())
      ; Deferred.choice (Pipe.downstream_flushed writer_pipe)
          (fun (_ : Pipe.Flushed_result.t) -> ()) ] >>> fun () ->
    don't_wait_for (teardown_connection r w));
  reader_pipe_r, writer_pipe

(* [Reader.of_pipe] will not close the pipe when the returned [Reader] is closed, so we
   manually do that ourselves.

   [Writer.of_pipe] will create a writer that will raise once the pipe is closed, so we
   set [raise_when_consumer_leaves] to false. *)
let reader_writer_of_pipes app_rd app_wr =
  Reader.of_pipe (Info.of_string "async_conduit_ssl_reader") app_rd >>= fun app_reader ->
  upon (Reader.close_finished app_reader) (fun () -> Pipe.close_read app_rd);
  Writer.of_pipe (Info.of_string "async_conduit_ssl_writer") app_wr >>| fun (app_writer,_) ->
  Writer.set_raise_when_consumer_leaves app_writer false;
  app_reader, app_writer

let connect r w =
  let net_to_ssl, ssl_to_net = reader_writer_pipes r w in
  let app_to_ssl, app_wr = Pipe.create () in
  let app_rd, ssl_to_app = Pipe.create () in
  Ssl.client
    ~verify_modes:[ Verify_none ]
    ~app_to_ssl
    ~ssl_to_app
    ~net_to_ssl
    ~ssl_to_net
    ()
  >>= function
  | Error error ->
    teardown_connection r w >>= fun () ->
    Error.raise error
  | Ok _ ->
    reader_writer_of_pipes app_rd app_wr >>| fun (app_reader, app_writer) ->
    (app_reader, app_writer)

let make_client ?client socket =
  match client with
  | Some client -> Deferred.return client
  | None ->
    let reader, writer = reader_writer_of_sock socket in
    connect reader writer

let listen ~crt_file ~key_file r w =
  let net_to_ssl, ssl_to_net = reader_writer_pipes r w in
  let app_to_ssl, app_wr = Pipe.create () in
  let app_rd, ssl_to_app = Pipe.create () in
  Ssl.server
    ~crt_file
    ~key_file
    ~app_to_ssl
    ~ssl_to_app
    ~net_to_ssl
    ~ssl_to_net
    ()
  >>= function
  | Error error ->
    teardown_connection r w >>= fun () ->
    Error.raise error
  | Ok _ ->
    reader_writer_of_pipes app_rd app_wr >>| fun (app_reader, app_writer) ->
    (app_reader, app_writer)

let make_server ?server ?certfile ?keyfile socket =
  match server, certfile, keyfile with
  | Some server, _, _ -> Deferred.return server
  | None, Some crt_file, Some key_file ->
    let reader, writer = reader_writer_of_sock socket in
    listen ~crt_file ~key_file reader writer
  | _ ->
    failwith "Certfile and Keyfile required when server isn't provided"
