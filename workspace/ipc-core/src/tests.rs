use super::*;

fn meta(label: u32) -> MsgMeta {
    MsgMeta {
        label,
        data_len: 16,
        flags: 0,
    }
}

fn meta_len(label: u32, data_len: u32) -> MsgMeta {
    MsgMeta {
        label,
        data_len,
        flags: 0,
    }
}

fn xfer(handle: Handle, rights: u32, mode: u32) -> CapXfer {
    CapXfer {
        handle: handle.raw(),
        rights,
        mode,
    }
}

fn pair() -> (IpcCore, ProcId, ProcId) {
    let mut c = IpcCore::new();
    let server = c.create_process();
    let client = c.create_process();
    (c, server, client)
}

fn make_ep(c: &mut IpcCore, owner: ProcId, depth: u32) -> (u64, Handle) {
    let h = c.ep_create(owner, depth, 0).unwrap();
    let id = c.endpoint_of(owner, h).unwrap();
    (id, h)
}

/// Move a handle between simulated processes. This stands in for the §8
/// namespace bootstrap (which grants SEND/EP_XFER) that the model omits.
fn hand(c: &mut IpcCore, from: ProcId, to: ProcId, h: Handle) -> Handle {
    let e = c.procs[from.0 as usize].table.remove(h).unwrap();
    c.procs[to.0 as usize].table.insert(e).unwrap()
}

/// Simulate the rights that `NS_LOOKUP` would grant (§8): the model's mint
/// only ever derives `EP_SEND`, so transfer rights are injected in tests.
fn grant(c: &mut IpcCore, p: ProcId, h: Handle, rights: u32) {
    c.procs[p.0 as usize].table.get_mut(h).unwrap().rights |= rights;
}

fn grant_xfer(c: &mut IpcCore, p: ProcId, h: Handle) {
    grant(c, p, h, EP_XFER);
}

fn make_send(
    c: &mut IpcCore,
    owner: ProcId,
    client: ProcId,
    recv_h: Handle,
    badge: u64,
    generic: u32,
) -> Handle {
    let h = c.ipc_mint(owner, recv_h, badge, generic).unwrap();
    hand(c, owner, client, h)
}

fn live(c: &IpcCore, p: ProcId, h: Handle) -> bool {
    c.procs[p.0 as usize].table.get(h).is_ok()
}

fn rights_of(c: &IpcCore, p: ProcId, h: Handle) -> u32 {
    c.procs[p.0 as usize].table.get(h).unwrap().rights
}

fn table_live(c: &IpcCore, p: ProcId) -> usize {
    c.procs[p.0 as usize]
        .table
        .slots
        .iter()
        .filter(|s| s.entry.is_some())
        .count()
}

// --- handles and creation ----------------------------------------------

#[test]
fn create_handle_has_no_send_right() {
    let (mut c, server, _client) = pair();
    let recv = c.ep_create(server, 0, 0).unwrap();
    let rights = rights_of(&c, server, recv);
    assert_eq!(rights & EP_SEND, 0);
    assert_eq!(rights & EP_RECV, EP_RECV);
    assert_eq!(rights & EP_MINT, EP_MINT);
    assert_eq!(rights & RIGHT_WAIT, RIGHT_WAIT);
    assert_eq!(rights & RIGHT_INSPECT, RIGHT_INSPECT);

    // The RECV handle cannot send.
    assert_eq!(
        c.ep_send(server, recv, meta(1), Vec::new(), true),
        Err(Error::Perm)
    );

    let send = c.ipc_mint(server, recv, 7, RIGHT_TRANSFER).unwrap();
    let rights = rights_of(&c, server, send);
    assert_eq!(rights & EP_SEND, EP_SEND);
    assert_eq!(rights & EP_RECV, 0);
    assert_eq!(rights & EP_MINT, 0);
}

#[test]
fn mint_requires_explicit_badge_and_mint_right() {
    let (mut c, server, _client) = pair();
    let (_, recv) = make_ep(&mut c, server, 0);

    // Badge 0 means unbadged and is allowed.
    let unbadged = c.ipc_mint(server, recv, 0, RIGHT_TRANSFER).unwrap();
    c.ep_send(server, unbadged, meta(1), Vec::new(), true)
        .unwrap();
    assert_eq!(c.ep_recv(server, recv, 4096, 4, true).unwrap().badge, 0);

    // An explicit badge is stored on the handle and delivered verbatim.
    let badged = c.ipc_mint(server, recv, 0x1234, RIGHT_TRANSFER).unwrap();
    c.ep_send(server, badged, meta(2), Vec::new(), true)
        .unwrap();
    assert_eq!(
        c.ep_recv(server, recv, 4096, 4, true).unwrap().badge,
        0x1234
    );

    // A SEND handle lacks EP_MINT and cannot mint.
    assert_eq!(
        c.ipc_mint(server, unbadged, 9, RIGHT_TRANSFER),
        Err(Error::Perm)
    );
}

#[test]
fn queue_depth_enforced_eagain() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 2);
    let send = make_send(&mut c, server, client, recv, 9, RIGHT_TRANSFER);

    c.ep_send(client, send, meta(1), Vec::new(), true).unwrap();
    c.ep_send(client, send, meta(2), Vec::new(), true).unwrap();
    // Full: EAGAIN with or without IPC_NONBLOCK (the model never blocks).
    assert_eq!(
        c.ep_send(client, send, meta(3), Vec::new(), true),
        Err(Error::Again)
    );
    assert_eq!(
        c.ep_send(client, send, meta(3), Vec::new(), false),
        Err(Error::Again)
    );
    assert_eq!(c.queued_len(ep), 2);

    // Depth 0 selects 16; out of range is EINVAL.
    let (ep0, _) = make_ep(&mut c, server, 0);
    assert_eq!(c.endpoint_queue_depth(ep0), Some(16));
    assert_eq!(c.ep_create(server, 257, 0), Err(Error::Inval));
}

#[test]
fn stale_handle_after_slot_reuse_is_bad_handle() {
    let mut c = IpcCore::new();
    let p = c.create_process();
    let h1 = c.ep_create(p, 0, 0).unwrap();
    c.handle_close(p, h1).unwrap();
    let h2 = c.ep_create(p, 0, 0).unwrap();
    assert_eq!(h2.index(), h1.index());
    assert_ne!(h2.generation(), h1.generation());
    // The old handle must not resolve to the new object.
    assert_eq!(c.handle_close(p, h1), Err(Error::BadHandle));
    assert_eq!(c.ep_recv(p, h1, 4096, 4, true), Err(Error::BadHandle));
    assert!(live(&c, p, h2));
}

#[test]
fn handle_generation_survives_reuse() {
    let mut c = IpcCore::new();
    let p = c.create_process();
    let h1 = c.ep_create(p, 0, 0).unwrap();
    let (idx, gen) = (h1.index(), h1.generation());
    c.handle_close(p, h1).unwrap();
    let h2 = c.ep_create(p, 0, 0).unwrap();
    assert_eq!(h2.index(), idx);
    assert_eq!(h2.generation(), gen + 1);
    assert_eq!(h1.raw() >> 56, 0);
    assert!(!Handle(0).is_valid());
}

// --- send validation -----------------------------------------------------

#[test]
fn send_validation_is_atomic_on_failure() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    grant_xfer(&mut c, client, send);
    let src = make_send(&mut c, server, client, recv, 2, RIGHT_TRANSFER);
    let no_transfer = make_send(&mut c, server, client, recv, 3, 0);
    grant(&mut c, client, src, RIGHT_TRANSFER);
    let before = table_live(&c, client);

    // Oversized payload.
    assert_eq!(
        c.ep_send(client, send, meta_len(1, MAX_DATA_LEN + 1), vec![], true),
        Err(Error::Inval)
    );
    // Too many capabilities.
    assert_eq!(
        c.ep_send(
            client,
            send,
            meta(1),
            vec![xfer(src, RIGHTS_SAME, XFER_MOVE); MAX_TRANSFER_CAPS + 1],
            true
        ),
        Err(Error::Inval)
    );
    // Bad transfer mode.
    assert_eq!(
        c.ep_send(client, send, meta(1), vec![xfer(src, RIGHTS_SAME, 9)], true),
        Err(Error::Inval)
    );
    // Source lacks RIGHT_TRANSFER.
    assert_eq!(
        c.ep_send(
            client,
            send,
            meta(1),
            vec![xfer(no_transfer, RIGHTS_SAME, XFER_MOVE)],
            true
        ),
        Err(Error::Perm)
    );
    // COPY requires RIGHT_DUPLICATE.
    assert_eq!(
        c.ep_send(
            client,
            send,
            meta(1),
            vec![xfer(src, RIGHTS_SAME, XFER_COPY)],
            true
        ),
        Err(Error::Perm)
    );

    assert_eq!(c.queued_len(ep), 0);
    assert_eq!(table_live(&c, client), before);
}

#[test]
fn xfer_move_removes_source_and_installs_receiver_handle() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    grant_xfer(&mut c, client, send);
    let src = make_send(&mut c, server, client, recv, 2, RIGHT_TRANSFER);
    grant(&mut c, client, src, RIGHT_TRANSFER);
    let src_rights = rights_of(&c, client, src);

    c.ep_send(
        client,
        send,
        meta(1),
        vec![xfer(src, RIGHTS_SAME, XFER_MOVE)],
        true,
    )
    .unwrap();
    // MOVE: the source disappeared from the sender's table.
    assert!(!live(&c, client, src));
    assert_eq!(c.queued_len(ep), 1);

    let r = c.ep_recv(server, recv, 4096, 4, true).unwrap();
    assert_eq!(r.kind, MSG_KIND_SEND);
    assert_eq!(r.sender_silo, client.0);
    assert_eq!(r.caps.len(), 1);
    assert_eq!(r.caps[0].rights, src_rights);
    assert_eq!(r.caps[0].obj_type, 1);
    assert!(live(&c, server, Handle::from_raw(r.caps[0].handle)));
}

#[test]
fn xfer_copy_requires_duplicate_and_keeps_source() {
    let (mut c, server, client) = pair();
    let (_, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    grant_xfer(&mut c, client, send);
    let src = make_send(
        &mut c,
        server,
        client,
        recv,
        2,
        RIGHT_TRANSFER | RIGHT_DUPLICATE,
    );
    grant(&mut c, client, src, RIGHT_TRANSFER | RIGHT_DUPLICATE);
    let src_rights = rights_of(&c, client, src);

    c.ep_send(
        client,
        send,
        meta(1),
        vec![xfer(src, RIGHTS_SAME, XFER_COPY)],
        true,
    )
    .unwrap();
    // COPY: the sender keeps its handle.
    assert!(live(&c, client, src));

    let r = c.ep_recv(server, recv, 4096, 4, true).unwrap();
    assert_eq!(r.caps.len(), 1);
    assert_eq!(r.caps[0].rights, src_rights);
}

#[test]
fn xfer_requires_ep_xfer_on_destination() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    let src = make_send(&mut c, server, client, recv, 2, RIGHT_TRANSFER);
    grant(&mut c, client, src, RIGHT_TRANSFER);

    assert_eq!(
        c.ep_send(
            client,
            send,
            meta(1),
            vec![xfer(src, RIGHTS_SAME, XFER_MOVE)],
            true
        ),
        Err(Error::Perm)
    );
    assert_eq!(c.queued_len(ep), 0);

    grant_xfer(&mut c, client, send);
    c.ep_send(
        client,
        send,
        meta(1),
        vec![xfer(src, RIGHTS_SAME, XFER_MOVE)],
        true,
    )
    .unwrap();
    assert_eq!(c.queued_len(ep), 1);
}

#[test]
fn received_caps_are_attenuated() {
    let (mut c, server, client) = pair();
    let (_, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    grant_xfer(&mut c, client, send);
    // EP_SEND is held; RIGHT_INSPECT is not, so it is stripped.
    let src = make_send(&mut c, server, client, recv, 2, RIGHT_TRANSFER);
    grant(&mut c, client, src, RIGHT_TRANSFER);

    c.ep_send(
        client,
        send,
        meta(1),
        vec![xfer(
            src,
            EP_SEND | RIGHT_TRANSFER | RIGHT_INSPECT,
            XFER_MOVE,
        )],
        true,
    )
    .unwrap();
    let r = c.ep_recv(server, recv, 4096, 4, true).unwrap();
    assert_eq!(r.caps[0].rights, EP_SEND | RIGHT_TRANSFER);
}

// --- receive -------------------------------------------------------------

#[test]
fn recv_emsgsize_keeps_message_queued() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    c.ep_call(client, send, meta_len(1, 32), (0, 0), Vec::new(), true)
        .unwrap();

    assert_eq!(c.ep_recv(server, recv, 31, 4, true), Err(Error::MsgSize));
    assert_eq!(c.queued_len(ep), 1);
    assert_eq!(c.head_requirements(ep), Some((32, 0)));

    let r = c.ep_recv(server, recv, 32, 4, true).unwrap();
    assert_eq!(r.kind, MSG_KIND_CALL);
    assert_eq!(c.queued_len(ep), 0);
}

#[test]
fn recv_enospc_keeps_message_queued() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    grant_xfer(&mut c, client, send);
    let src = make_send(&mut c, server, client, recv, 2, RIGHT_TRANSFER);
    grant(&mut c, client, src, RIGHT_TRANSFER);

    // Fill the server's handle table to its limit.
    let mut last = c
        .ipc_mint(server, recv, 0, RIGHT_DUPLICATE)
        .expect("mint dup");
    grant(&mut c, server, last, RIGHT_DUPLICATE);
    loop {
        match c.handle_duplicate(server, last, RIGHT_DUPLICATE) {
            Ok(h) => last = h,
            Err(Error::NoSpace) => break,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!(c.procs[server.0 as usize].table.available(), 0);

    let call = c
        .ep_call(
            client,
            send,
            meta(1),
            (4096, 4),
            vec![xfer(src, RIGHTS_SAME, XFER_MOVE)],
            true,
        )
        .unwrap();
    // 1 transferred cap + 1 reply slot cannot be reserved.
    assert_eq!(c.ep_recv(server, recv, 4096, 4, true), Err(Error::NoSpace));
    assert_eq!(c.queued_len(ep), 1);
    assert_eq!(c.call_state(call), Some(CallState::Queued));
    // The MOVE source was detached at commit, but the recv still has not run.
    assert!(!live(&c, client, src));
}

// --- notifications -------------------------------------------------------

#[test]
fn bound_notification_precedes_queued_messages() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let notif = c.notif_create(server).unwrap();
    c.ep_bind_notif(server, recv, notif).unwrap();
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    c.ep_send(client, send, meta(1), Vec::new(), true).unwrap();

    c.notif_signal(server, notif, 0b1010).unwrap();
    let r = c.ep_recv(server, recv, 4096, 4, true).unwrap();
    assert_eq!(r.kind, MSG_KIND_NOTIF);
    assert_eq!(r.badge, 0b1010);
    assert!(r.reply.is_none());
    // The queued message is still there, delivered second.
    assert_eq!(c.queued_len(ep), 1);
    assert_eq!(
        c.ep_recv(server, recv, 4096, 4, true).unwrap().kind,
        MSG_KIND_SEND
    );
}

#[test]
fn notif_signal_is_masked_by_minted_badge() {
    let (mut c, server, _client) = pair();
    let n = c.notif_create(server).unwrap();
    let sig = c.ipc_mint(server, n, 0b0011, RIGHT_WAIT).unwrap();
    c.notif_signal(server, sig, 0b1111).unwrap();
    assert_eq!(c.notif_wait(server, n, true).unwrap(), 0b0011);
    assert_eq!(c.notif_wait(server, n, true), Err(Error::Again));
}

// --- reply ---------------------------------------------------------------

#[test]
fn reply_handle_close_gives_pipe() {
    let (mut c, server, client) = pair();
    let (_, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    let call = c
        .ep_call(client, send, meta(1), (0, 0), Vec::new(), true)
        .unwrap();
    let reply = c
        .ep_recv(server, recv, 4096, 4, true)
        .unwrap()
        .reply
        .unwrap();

    c.handle_close(server, reply).unwrap();
    // The caller observes EPIPE as a Cancelled call.
    assert_eq!(c.call_state(call), Some(CallState::Cancelled));
    assert_eq!(c.read_reply(call), None);
    // The consumed handle is gone.
    assert_eq!(c.ep_reply(server, reply, meta(2)), Err(Error::BadHandle));
}

#[test]
fn reply_recv_completes_reply_before_recv_failure() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    let a = c
        .ep_call(client, send, meta(1), (0, 0), Vec::new(), true)
        .unwrap();
    let reply = c
        .ep_recv(server, recv, 4096, 4, true)
        .unwrap()
        .reply
        .unwrap();
    let b = c
        .ep_call(client, send, meta(2), (0, 0), Vec::new(), true)
        .unwrap();

    // Reply to `a` completes even though the following recv is too small.
    assert_eq!(
        c.ep_reply_recv(server, reply, meta(9), recv, 0, 0, true),
        Err(Error::MsgSize)
    );
    assert_eq!(c.call_state(a), Some(CallState::Done));
    assert_eq!(c.read_reply(a), Some(meta(9)));
    assert_eq!(c.call_state(b), Some(CallState::Queued));
    assert_eq!(c.queued_len(ep), 1);
}

// --- lifetime ------------------------------------------------------------

#[test]
fn closing_last_recv_handle_closes_endpoint() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    let call = c
        .ep_call(client, send, meta(1), (0, 0), Vec::new(), true)
        .unwrap();

    c.handle_close(server, recv).unwrap();
    assert_eq!(c.endpoint_alive(ep), Some(false));
    assert_eq!(c.queued_len(ep), 0);
    assert_eq!(c.call_state(call), Some(CallState::Cancelled));
    // SEND handles survive as tombstones but fail with EPIPE.
    assert!(live(&c, client, send));
    assert_eq!(
        c.ep_send(client, send, meta(2), Vec::new(), true),
        Err(Error::Pipe)
    );
}

#[test]
fn exit_process_closes_handles() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    let call = c
        .ep_call(client, send, meta(1), (0, 0), Vec::new(), true)
        .unwrap();
    assert!(live(&c, server, recv));

    c.exit_process(server);
    assert_eq!(c.endpoint_alive(ep), Some(false));
    assert_eq!(c.queued_len(ep), 0);
    assert_eq!(c.call_state(call), Some(CallState::Cancelled));
    assert!(!live(&c, server, recv));
    assert_eq!(
        c.ep_send(client, send, meta(2), Vec::new(), true),
        Err(Error::Pipe)
    );
    // A dead process cannot use its (now cleared) table.
    assert_eq!(c.ep_create(server, 0, 0), Err(Error::BadHandle));
}

// --- call/reply legacy intents ------------------------------------------

#[test]
fn call_record_exists_before_server_sees_message() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 7, RIGHT_TRANSFER);

    let id = c
        .ep_call(client, send, meta(1), (4096, 4), Vec::new(), true)
        .unwrap();
    assert_eq!(c.call_state(id), Some(CallState::Queued));
    assert_eq!(c.queued_len(ep), 1);
    assert_eq!(c.reply_buf_cap(id), Some((4096, 4)));

    let r = c.ep_recv(server, recv, 4096, 4, true).unwrap();
    assert_eq!(r.badge, 7);
    assert_eq!(c.call_state(id), Some(CallState::Received));
    let reply = r.reply.unwrap();
    assert_eq!(c.call_caller(id), Some((client, send.generation())));

    c.ep_reply(server, reply, meta(2)).unwrap();
    assert_eq!(c.call_state(id), Some(CallState::Done));
    assert_eq!(c.read_reply(id), Some(meta(2)));
}

#[test]
fn double_reply_is_bad_handle() {
    let (mut c, server, client) = pair();
    let (_, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    c.ep_call(client, send, meta(1), (0, 0), Vec::new(), true)
        .unwrap();
    let reply = c
        .ep_recv(server, recv, 4096, 4, true)
        .unwrap()
        .reply
        .unwrap();
    c.ep_reply(server, reply, meta(2)).unwrap();
    assert_eq!(c.ep_reply(server, reply, meta(3)), Err(Error::BadHandle));
}

#[test]
fn any_holder_can_reply_out_of_order() {
    let (mut c, server, client) = pair();
    let (_, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    let a = c
        .ep_call(client, send, meta(1), (0, 0), Vec::new(), true)
        .unwrap();
    let b = c
        .ep_call(client, send, meta(2), (0, 0), Vec::new(), true)
        .unwrap();
    let a_reply = c
        .ep_recv(server, recv, 4096, 4, true)
        .unwrap()
        .reply
        .unwrap();
    let b_reply = c
        .ep_recv(server, recv, 4096, 4, true)
        .unwrap()
        .reply
        .unwrap();

    c.ep_reply(server, b_reply, meta(20)).unwrap();
    c.ep_reply(server, a_reply, meta(10)).unwrap();
    assert_eq!(c.read_reply(a), Some(meta(10)));
    assert_eq!(c.read_reply(b), Some(meta(20)));
}

#[test]
fn late_reply_after_cancel_does_not_reach_next_call() {
    let (mut c, server, client) = pair();
    let (_, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);

    let a = c
        .ep_call(client, send, meta(1), (0, 0), Vec::new(), true)
        .unwrap();
    let a_reply = c
        .ep_recv(server, recv, 4096, 4, true)
        .unwrap()
        .reply
        .unwrap();
    c.cancel_call(client, a).unwrap();
    assert_eq!(c.call_state(a), Some(CallState::Cancelled));

    let b = c
        .ep_call(client, send, meta(2), (0, 0), Vec::new(), true)
        .unwrap();
    let b_reply = c
        .ep_recv(server, recv, 4096, 4, true)
        .unwrap()
        .reply
        .unwrap();

    // The stale reply handle is consumed and fails with EPIPE.
    assert_eq!(c.ep_reply(server, a_reply, meta(10)), Err(Error::Pipe));
    assert_eq!(c.read_reply(b), None);
    assert_eq!(c.call_state(b), Some(CallState::Received));

    c.ep_reply(server, b_reply, meta(11)).unwrap();
    assert_eq!(c.read_reply(b), Some(meta(11)));
    assert_eq!(c.read_reply(a), None);
}

#[test]
fn cancel_queued_call_never_reaches_server() {
    let (mut c, server, client) = pair();
    let (ep, recv) = make_ep(&mut c, server, 8);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    let a = c
        .ep_call(client, send, meta(1), (0, 0), Vec::new(), true)
        .unwrap();
    c.cancel_call(client, a).unwrap();
    assert_eq!(c.queued_len(ep), 0);
    assert_eq!(c.call_state(a), Some(CallState::Cancelled));
    assert_eq!(c.ep_recv(server, recv, 4096, 4, true), Err(Error::Again));
}

#[test]
fn badge_comes_from_capability_not_message() {
    let (mut c, server, client) = pair();
    let (_, recv) = make_ep(&mut c, server, 8);
    let a = make_send(&mut c, server, client, recv, 0x11, RIGHT_TRANSFER);
    let b = make_send(&mut c, server, client, recv, 0x22, RIGHT_TRANSFER);
    // Identical message content, different capabilities.
    c.ep_send(client, a, meta(7), Vec::new(), true).unwrap();
    c.ep_send(client, b, meta(7), Vec::new(), true).unwrap();
    let first = c.ep_recv(server, recv, 4096, 4, true).unwrap();
    let second = c.ep_recv(server, recv, 4096, 4, true).unwrap();
    assert_eq!(first.badge, 0x11);
    assert_eq!(second.badge, 0x22);
}

#[test]
fn ids_are_never_reused() {
    let (mut c, server, client) = pair();
    let (ep1, recv) = make_ep(&mut c, server, 8);
    let (ep2, _) = make_ep(&mut c, server, 8);
    assert!(ep2 > ep1);
    let send = make_send(&mut c, server, client, recv, 1, RIGHT_TRANSFER);
    let a = c
        .ep_call(client, send, meta(1), (0, 0), Vec::new(), true)
        .unwrap();
    let b = c
        .ep_call(client, send, meta(2), (0, 0), Vec::new(), true)
        .unwrap();
    assert!(b.0 > a.0);
}

#[test]
fn handle_duplicate_shrinks_rights() {
    let (mut c, server, _client) = pair();
    let recv = c.ep_create(server, 0, 0).unwrap();
    // The create handle has no RIGHT_DUPLICATE, so duplication fails.
    assert_eq!(c.handle_duplicate(server, recv, EP_RECV), Err(Error::Perm));
    let send = c
        .ipc_mint(server, recv, 5, RIGHT_DUPLICATE | RIGHT_TRANSFER)
        .unwrap();
    grant(&mut c, server, send, RIGHT_DUPLICATE | RIGHT_TRANSFER);
    let shrunk = c
        .handle_duplicate(server, send, RIGHT_TRANSFER | EP_RECV)
        .unwrap();
    let rights = rights_of(&c, server, shrunk);
    assert_eq!(rights & RIGHT_TRANSFER, RIGHT_TRANSFER);
    // EP_RECV is not held by the source, so it is stripped.
    assert_eq!(rights & EP_RECV, 0);
}

// --- deterministic pseudo-random stress ---------------------------------

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn pick(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

fn rnd_generic(r: &mut Lcg) -> u32 {
    let mut v = 0;
    for bit in [RIGHT_TRANSFER, RIGHT_DUPLICATE, RIGHT_WAIT, RIGHT_INSPECT] {
        if r.next() & 1 != 0 {
            v |= bit;
        }
    }
    v
}

fn pick_h(list: &[Handle], r: &mut Lcg) -> Option<Handle> {
    if list.is_empty() {
        None
    } else {
        Some(list[r.pick(list.len())])
    }
}

fn rnd_caps(c: &IpcCore, p: ProcId, list: &[Handle], r: &mut Lcg) -> Vec<CapXfer> {
    let n = r.pick(3);
    let mut out = Vec::new();
    for _ in 0..n {
        if list.is_empty() {
            break;
        }
        let h = list[r.pick(list.len())];
        if !live(c, p, h) || out.iter().any(|x: &CapXfer| x.handle == h.raw()) {
            continue;
        }
        let mode = if r.next() & 1 == 0 {
            XFER_MOVE
        } else {
            XFER_COPY
        };
        let rights = if r.next() & 1 == 0 {
            RIGHTS_SAME
        } else {
            (r.next() as u32) & (EP_SEND | EP_RECV | RIGHT_TRANSFER | RIGHT_DUPLICATE)
        };
        out.push(xfer(h, rights, mode));
    }
    out
}

fn check_invariants(c: &IpcCore) {
    for ep in &c.endpoints {
        assert!(
            ep.queue.len() <= ep.queue_depth as usize,
            "queue over depth"
        );
        for m in &ep.queue {
            assert!(m.caps.len() <= MAX_TRANSFER_CAPS, "too many caps");
            if let Some(cid) = m.call {
                assert_ne!(
                    c.call_state(CallId(cid)),
                    Some(CallState::Cancelled),
                    "queued message for a cancelled call"
                );
            }
        }
        for rec in &ep.calls {
            if rec.state == CallState::Done {
                assert!(rec.reply_msg.is_some(), "Done call without a reply");
            } else {
                assert!(rec.reply_msg.is_none(), "reply on a non-Done call");
            }
        }
        if !ep.alive {
            assert_eq!(ep.queue.len(), 0, "closed endpoint still queued");
        }
        if ep.pending_bits != 0 {
            assert!(ep.alive, "pending bits on a closed endpoint");
            assert!(ep.bound_notif.is_some(), "pending bits without a binding");
        }
    }
    for p in &c.procs {
        if !p.alive {
            continue;
        }
        for slot in &p.table.slots {
            if let Some(Entry {
                rights,
                kind: ObjKind::Endpoint(id),
                ..
            }) = slot.entry
            {
                if rights & EP_RECV != 0 {
                    assert!(
                        c.endpoints[id as usize].alive,
                        "live EP_RECV handle to a closed endpoint"
                    );
                }
            }
        }
    }
}

#[test]
fn deterministic_stress() {
    let mut c = IpcCore::new();
    let mut procs = [c.create_process(), c.create_process()];
    let mut handles: [Vec<Handle>; 2] = [Vec::new(), Vec::new()];
    let mut eps: Vec<u64> = Vec::new();
    let mut calls: Vec<(ProcId, CallId)> = Vec::new();
    let mut rng = Lcg(0x1234_5678_9abc_def0);

    for step in 0..12_000 {
        let pi = rng.pick(2);
        let p = procs[pi];
        match rng.pick(12) {
            0 => {
                if handles[pi].len() < 100 {
                    if let Ok(h) = c.ep_create(p, rng.pick(4) as u32, 0) {
                        eps.push(c.endpoint_of(p, h).unwrap());
                        handles[pi].push(h);
                    }
                }
            }
            1 => {
                if let Some(src) = pick_h(&handles[pi], &mut rng) {
                    let badge = rng.next() & 0xFFFF;
                    if let Ok(h) = c.ipc_mint(p, src, badge, rnd_generic(&mut rng)) {
                        let extra = if rng.next() & 1 != 0 {
                            EP_XFER | RIGHT_TRANSFER | RIGHT_DUPLICATE
                        } else {
                            EP_XFER
                        };
                        if let Some(e) = c.procs[pi].table.get_mut(h).ok() {
                            e.rights |= extra;
                        }
                        handles[pi].push(h);
                    }
                }
            }
            2 => {
                if let Some(h) = pick_h(&handles[pi], &mut rng) {
                    let caps = rnd_caps(&c, p, &handles[pi], &mut rng);
                    let _ = c.ep_send(
                        p,
                        h,
                        meta_len(rng.next() as u32, (rng.next() % 64) as u32),
                        caps,
                        true,
                    );
                }
            }
            3 => {
                if let Some(h) = pick_h(&handles[pi], &mut rng) {
                    let caps = rnd_caps(&c, p, &handles[pi], &mut rng);
                    if let Ok(id) = c.ep_call(
                        p,
                        h,
                        meta_len(rng.next() as u32, (rng.next() % 64) as u32),
                        (4096, 4),
                        caps,
                        true,
                    ) {
                        calls.push((p, id));
                    }
                }
            }
            4 => {
                if handles[pi].len() < 100 {
                    if let Ok(n) = c.notif_create(p) {
                        handles[pi].push(n);
                    }
                }
            }
            5 => {
                if let Some(h) = pick_h(&handles[pi], &mut rng) {
                    let _ = c.notif_signal(p, h, rng.next());
                }
            }
            6 => {
                if let Some(h) = pick_h(&handles[pi], &mut rng) {
                    let _ = c.notif_wait(p, h, true);
                }
            }
            7 => {
                if let Some(h) = pick_h(&handles[pi], &mut rng) {
                    let caps_cap = rng.pick(5) as u32;
                    let data_cap = rng.pick(65) as u32;
                    if let Ok(r) = c.ep_recv(p, h, data_cap, caps_cap, true) {
                        if let Some(reply) = r.reply {
                            handles[pi].push(reply);
                        }
                    }
                }
            }
            8 => {
                if let Some(h) = pick_h(&handles[pi], &mut rng) {
                    let _ = c.ep_reply(p, h, meta_len(rng.next() as u32, (rng.next() % 64) as u32));
                }
            }
            9 => {
                if !calls.is_empty() {
                    let (cp, cid) = calls[rng.pick(calls.len())];
                    let _ = c.cancel_call(cp, cid);
                }
            }
            10 => {
                if let Some(h) = pick_h(&handles[pi], &mut rng) {
                    let _ = c.handle_close(p, h);
                }
                // Bind a notification to an endpoint sometimes.
                if let (Some(ep_h), Some(n_h)) = (
                    pick_h(&handles[pi], &mut rng),
                    pick_h(&handles[pi], &mut rng),
                ) {
                    let _ = c.ep_bind_notif(p, ep_h, n_h);
                }
            }
            _ => {
                if handles[pi].len() > 110 {
                    c.exit_process(p);
                    procs[pi] = c.create_process();
                    handles[pi].clear();
                }
            }
        }

        check_invariants(&c);

        // Keep the working set bounded.
        if handles[pi].len() > 120 {
            c.exit_process(p);
            procs[pi] = c.create_process();
            handles[pi].clear();
        }
        if step % 400 == 399 {
            calls.retain(|(_, cid)| {
                !c.call_state(*cid)
                    .unwrap_or(CallState::Cancelled)
                    .is_terminal()
            });
            eps.retain(|id| c.endpoint_alive(*id) == Some(true));
        }
    }

    // Every retained call must be terminal or still in a valid live state.
    for (_, cid) in &calls {
        if let Some(state) = c.call_state(*cid) {
            assert!(matches!(
                state,
                CallState::Queued | CallState::Received | CallState::Done | CallState::Cancelled
            ));
        }
    }
    check_invariants(&c);
    let _ = eps;
}
