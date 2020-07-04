open Core
open Async

(** XXX(seliopou): Replace Angstrom.Buffered with a module like this, while
    also supporting growing the buffer. Clients can use this to buffer and the
    use the unbuffered interface for actually running the parser. *)
module Buffer : sig
  type t

  val create   : int -> t

  val get : t -> f:(Bigstring.t -> off:int -> len:int -> int) -> int
  val get' : t -> f:(Bigstring.t -> off:int -> len:int -> int * 'a) -> int * 'a
  val put : t -> f:(Bigstring.t -> off:int -> len:int -> int) -> int

  val to_iovec : t -> Bigstring.t Faraday.iovec
  val advance : t -> int -> unit
end= struct
  type t =
    { buffer      : Bigstring.t
    ; mutable off : int
    ; mutable len : int }

  let create size =
    let buffer = Bigstring.create size in
    { buffer; off = 0; len = 0 }
  ;;

  let compress t =
    if t.len = 0
    then begin
      t.off <- 0;
      t.len <- 0;
    end else if t.off > 0
    then begin
      Bigstring.blit ~src:t.buffer ~src_pos:t.off ~dst:t.buffer ~dst_pos:0 ~len:t.len;
      t.off <- 0;
    end
  ;;

  let advance t n =
    t.off <- t.off + n;
    t.len <- t.len - n;
    if t.len = 0
    then t.off <- 0
  ;;

  let get t ~f =
    let n = f t.buffer ~off:t.off ~len:t.len in
    advance t n;
    n
  ;;

  let get' t ~f =
    let n, result = f t.buffer ~off:t.off ~len:t.len in
    advance t n;
    n, result
  ;;

  let put t ~f =
    compress t;
    let n = f t.buffer ~off:(t.off + t.len) ~len:(Bigstring.length t.buffer - t.len) in
    t.len <- t.len + n;
    n
  ;;

  let to_iovec t =
    { Faraday.buffer = t.buffer; off = t.off; len = t.len }
end

let read fd buffer =
  let badfd fd = failwithf "read got back fd: %s" (Fd.to_string fd) () in
  let rec finish fd buffer result =
    let open Unix.Error in
    match result with
    | `Already_closed | `Ok 0 -> return `Eof
    | `Ok n                   -> return (`Ok n)
    | `Error (Unix.Unix_error ((EWOULDBLOCK | EAGAIN), _, _)) ->
      begin Fd.ready_to fd `Read
      >>= function
        | `Bad_fd -> badfd fd
        | `Closed -> return `Eof
        | `Ready  -> go fd buffer
      end
    | `Error (Unix.Unix_error (EBADF, _, _)) ->
      badfd fd
    | `Error exn ->
      Deferred.don't_wait_for (Fd.close fd);
      raise exn
  and go fd buffer  =
    if Fd.supports_nonblock fd then
      finish fd buffer
        (Fd.syscall fd ~nonblocking:true
          (fun file_descr ->
            Buffer.put buffer ~f:(fun bigstring ~off ~len ->
              Unix.Syscall_result.Int.ok_or_unix_error_exn ~syscall_name:"read"
                (Bigstring.read_assume_fd_is_nonblocking file_descr bigstring ~pos:off ~len))))
    else
      Fd.syscall_in_thread fd ~name:"read"
        (fun file_descr ->
          Buffer.put buffer ~f:(fun bigstring ~off ~len ->
            Bigstring.read file_descr bigstring ~pos:off ~len))
      >>= fun result -> finish fd buffer result
  in
  go fd buffer

module Cleartext_transport = struct
  type t = Fd.t

  let create t = t
  let read t buffer = read t buffer
  let writev t iovec = Faraday_async.writev_of_fd t iovec
end

module Tls_transport = struct
  type t =
    { fd : Fd.t
    ; write_to_fd : Bigstring.t Faraday.iovec list -> [ `Closed | `Ok of int ] Deferred.t
    ; mutable state : [ `Active of Tls.Engine.state | `Eof | `Error ]
    ; socket_read_buffer : Buffer.t
    ; socket_write_buffer : Buffer.t
    ; application_buffer : Buffer.t
    }

  let create fd tls_config ~read_buffer_size ~response_buffer_size =
    { fd
    ; write_to_fd = Faraday_async.writev_of_fd fd
    ; state = `Active (Tls.Engine.server tls_config)
    ; socket_read_buffer = Buffer.create read_buffer_size
    ; socket_write_buffer = Buffer.create response_buffer_size
    ; application_buffer = Buffer.create read_buffer_size
    }

  let write_to_socket t cstruct =
    let rec write_loop t (cstruct : Cstruct.t) ~already_buffered =
      if Int.(=) already_buffered cstruct.len
      then return (`Ok already_buffered)
      else (
        let buffered =
          Buffer.put t.socket_write_buffer ~f:(fun buf ~off ~len ->
            let copy = Int.min len cstruct.len in
            Bigstring.blit
              ~src:cstruct.buffer
              ~src_pos:cstruct.off
              ~dst:buf
              ~dst_pos:off
              ~len:copy;
            copy)
        in
        t.write_to_fd [ Buffer.to_iovec t.socket_write_buffer ]
        >>= function
        | `Closed -> return `Closed
        | `Ok flushed ->
          Buffer.advance t.socket_write_buffer flushed;
          write_loop t cstruct ~already_buffered:(already_buffered + buffered))
    in
    write_loop t cstruct ~already_buffered:0

  let read t =
    match t.state with
    | `Eof | `Error -> return `Eof
    | `Active tls ->
      read t.fd t.socket_read_buffer
      >>= begin function
      | `Eof -> return `Eof
      | `Ok _ ->
        let _, result =
          Buffer.get' t.socket_read_buffer ~f:(fun bigstring ~off ~len ->
            len,
            Tls.Engine.handle_tls tls (Cstruct.of_bigarray ~off ~len bigstring))
        in
        match result with
        | `Fail (failure, `Response response) ->
          t.state <- `Error;
          Log.Global.error "TLS error: %s" (Tls.Engine.string_of_failure failure);
          t.write_to_fd
            [ { Faraday.buffer = response.buffer
              ; off = response.off
              ; len = response.len
              }
            ]
          >>| fun (_ : [ `Closed | `Ok of int ]) -> `Eof
        | `Ok (state', `Response response, `Data data) ->
          let state' =
            match state' with
            | `Ok tls -> `Active tls
            | `Eof -> `Eof
            | `Alert alert ->
              Log.Global.error "TLS error: %s" (Tls.Packet.alert_type_to_string alert);
              `Error
          in
          t.state <- state';
          (match response with
           | None -> Deferred.unit
           | Some response ->
             t.write_to_fd
               [ { Faraday.buffer = response.buffer
                 ; off = response.off
                 ; len = response.len
                 }
               ]
             >>| fun (_ : [ `Closed | `Ok of int ]) -> ())
          >>=
      end
  ;;
end

open Httpaf

module Server = struct
  let create_connection_handler ?(config=Config.default) ~request_handler ~error_handler =
    fun client_addr socket ->
      let fd     = Socket.fd socket in
      let writev = Faraday_async.writev_of_fd fd in
      let request_handler = request_handler client_addr in
      let error_handler   = error_handler client_addr in
      let conn = Server_connection.create ~config ~error_handler request_handler in
      let read_complete = Ivar.create () in
      let buffer = Buffer.create config.read_buffer_size in
      let rec reader_thread () =
        match Server_connection.next_read_operation conn with
        | `Read ->
          (* Log.Global.printf "read(%d)%!" (Fd.to_int_exn fd); *)
          read fd buffer
          >>> begin function
            | `Eof  ->
              Buffer.get buffer ~f:(fun bigstring ~off ~len ->
                Server_connection.read_eof conn bigstring ~off ~len)
              |> ignore;
              reader_thread ()
            | `Ok _ ->
              Buffer.get buffer ~f:(fun bigstring ~off ~len ->
                Server_connection.read conn bigstring ~off ~len)
              |> ignore;
              reader_thread ()
          end
        | `Yield  ->
          (* Log.Global.printf "read_yield(%d)%!" (Fd.to_int_exn fd); *)
          Server_connection.yield_reader conn reader_thread
        | `Close ->
          (* Log.Global.printf "read_close(%d)%!" (Fd.to_int_exn fd); *)
          Ivar.fill read_complete ();
          if not (Fd.is_closed fd)
          then Socket.shutdown socket `Receive
      in
      let write_complete = Ivar.create () in
      let rec writer_thread () =
        match Server_connection.next_write_operation conn with
        | `Write iovecs ->
          (* Log.Global.printf "write(%d)%!" (Fd.to_int_exn fd); *)
          writev iovecs >>> fun result ->
            Server_connection.report_write_result conn result;
            writer_thread ()
        | `Yield ->
          (* Log.Global.printf "write_yield(%d)%!" (Fd.to_int_exn fd); *)
          Server_connection.yield_writer conn writer_thread;
        | `Close _ ->
          (* Log.Global.printf "write_close(%d)%!" (Fd.to_int_exn fd); *)
          Ivar.fill write_complete ();
          if not (Fd.is_closed fd)
          then Socket.shutdown socket `Send
      in
      let conn_monitor = Monitor.create () in
      Scheduler.within ~monitor:conn_monitor reader_thread;
      Scheduler.within ~monitor:conn_monitor writer_thread;
      Monitor.detach_and_iter_errors conn_monitor ~f:(fun exn ->
        Server_connection.report_exn conn exn);
      (* The Tcp module will close the file descriptor once this becomes determined. *)
      Deferred.all_unit
        [ Ivar.read read_complete
        ; Ivar.read write_complete ]
end

module Client = struct
  let request ?(config=Config.default) socket request ~error_handler ~response_handler =
    let fd     = Socket.fd socket in
    let writev = Faraday_async.writev_of_fd fd in
    let request_body, conn   =
      Client_connection.request request ~error_handler ~response_handler in
    let read_complete = Ivar.create () in
    let buffer = Buffer.create config.read_buffer_size in
    let rec reader_thread () =
      match Client_connection.next_read_operation conn with
      | `Read ->
        (* Log.Global.printf "read(%d)%!" (Fd.to_int_exn fd); *)
        read fd buffer
          >>> begin function
            | `Eof  ->
              Buffer.get buffer ~f:(fun bigstring ~off ~len ->
                Client_connection.read_eof conn bigstring ~off ~len)
              |> ignore;
              reader_thread ()
            | `Ok _ ->
              Buffer.get buffer ~f:(fun bigstring ~off ~len ->
                Client_connection.read conn bigstring ~off ~len)
              |> ignore;
              reader_thread ()
          end
      | `Close ->
        (* Log.Global.printf "read_close(%d)%!" (Fd.to_int_exn fd); *)
        Ivar.fill read_complete ();
        if not (Fd.is_closed fd)
        then Socket.shutdown socket `Receive
    in
    let write_complete = Ivar.create () in
    let rec writer_thread () =
      match Client_connection.next_write_operation conn with
      | `Write iovecs ->
        (* Log.Global.printf "write(%d)%!" (Fd.to_int_exn fd); *)
        writev iovecs >>> fun result ->
          Client_connection.report_write_result conn result;
          writer_thread ()
      | `Yield ->
        (* Log.Global.printf "write_yield(%d)%!" (Fd.to_int_exn fd); *)
        Client_connection.yield_writer conn writer_thread;
      | `Close _ ->
        (* Log.Global.printf "write_close(%d)%!" (Fd.to_int_exn fd); *)
        Ivar.fill write_complete ();
    in
    let conn_monitor = Monitor.create () in
    Scheduler.within ~monitor:conn_monitor reader_thread;
    Scheduler.within ~monitor:conn_monitor writer_thread;
    Monitor.detach_and_iter_errors conn_monitor ~f:(fun exn ->
      Client_connection.report_exn conn exn);
    don't_wait_for (
      Deferred.all_unit
        [ Ivar.read read_complete
        ; Ivar.read write_complete ]
      >>| fun () ->
        if not (Fd.is_closed fd)
        then don't_wait_for (Fd.close fd));
    request_body
end
