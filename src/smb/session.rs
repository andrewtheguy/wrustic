// Connection setup: NEGOTIATE, SESSION_SETUP, TREE_CONNECT and the trivial
// session-scoped commands.
//
// Authentication here is deliberately a formality. The share is bound to the
// loopback interface and serves one immutable snapshot read-only, so the server
// completes the NTLMSSP exchange without checking anything and marks the result
// as a guest session. SMB2_SESSION_FLAG_IS_GUEST is what makes this work: a
// guest session has no signing key, so the client stops expecting signatures.
//
// This is exactly the configuration Windows 11 24H2 refuses (it requires
// signing, and signing is incompatible with guest), which is why this server
// targets Linux and macOS clients only.

use anyhow::Result;

use super::proto::{
    CAP_LARGE_MTU, DIALECT_SMB_2_1, HEADER_LEN, SESSION_FLAG_IS_GUEST, SHARE_TYPE_DISK,
    SHARE_TYPE_PIPE, SIGNING_ENABLED, access, status, to_filetime,
};
use super::wire::{Reader, Writer, der_tlv, from_utf16le, utf16le};

/// Ceiling on a single READ, and on the transact/write sizes we advertise.
/// Bounds one response allocation; also caps how much a client asks for at once.
pub(crate) const MAX_READ_SIZE: u32 = 1024 * 1024;

/// OID 1.3.6.1.5.5.2 — SPNEGO.
const OID_SPNEGO: &[u8] = &[0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
/// OID 1.3.6.1.4.1.311.2.2.10 — NTLMSSP.
const OID_NTLMSSP: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A,
];

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NTLMSSP_NEGOTIATE: u32 = 1;
const NTLMSSP_AUTHENTICATE: u32 = 3;

/// The name reported as the NTLM target and the SMB volume label.
const SERVER_NAME: &str = "WRUSTIC";

/// Build the SPNEGO `NegTokenInit` advertised in the NEGOTIATE response: a
/// mechTypes list containing NTLMSSP and nothing else. Offering only one
/// mechanism keeps the client from trying Kerberos first and stalling on a KDC
/// lookup that cannot succeed.
pub(crate) fn spnego_neg_token_init() -> Vec<u8> {
    let mech_types = der_tlv(0x30, OID_NTLMSSP);
    let mech_types_ctx = der_tlv(0xA0, &mech_types);
    let inner = der_tlv(0x30, &mech_types_ctx);
    let neg_ctx = der_tlv(0xA0, &inner);

    let mut body = Vec::with_capacity(OID_SPNEGO.len() + neg_ctx.len());
    body.extend_from_slice(OID_SPNEGO);
    body.extend_from_slice(&neg_ctx);
    der_tlv(0x60, &body)
}

/// SPNEGO `NegTokenResp` carrying the NTLMSSP challenge, with negState
/// accept-incomplete (1) — "keep going, here is my half".
fn spnego_challenge(ntlmssp: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&der_tlv(0xA0, &[0x0A, 0x01, 0x01]));
    inner.extend_from_slice(&der_tlv(0xA1, OID_NTLMSSP));
    inner.extend_from_slice(&der_tlv(0xA2, &der_tlv(0x04, ntlmssp)));
    der_tlv(0xA1, &der_tlv(0x30, &inner))
}

/// SPNEGO `NegTokenResp` with negState accept-completed (0) — "you're in".
fn spnego_accept() -> Vec<u8> {
    let inner = der_tlv(0xA0, &[0x0A, 0x01, 0x00]);
    der_tlv(0xA1, &der_tlv(0x30, &inner))
}

/// How the client framed its NTLMSSP token — and therefore how the reply must
/// be framed.
///
/// This is not a detail we get to choose. `smbclient` negotiates SPNEGO and
/// expects a `NegTokenResp` back; the Linux kernel client with `sec=none` uses
/// **raw** NTLMSSP and rejects an SPNEGO-wrapped reply outright with
/// "blob signature incorrect", because it parses the response buffer by
/// checking for the NTLMSSP magic at offset zero. Mirroring whatever the client
/// sent satisfies both without having to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// The token is the security buffer, starting at offset zero.
    Raw,
    /// The token is wrapped in a SPNEGO NegTokenInit/NegTokenResp.
    Spnego,
}

/// Locate an NTLMSSP message inside a security blob, and note how it was
/// framed.
///
/// The SPNEGO case is DER, but writing a DER parser to reach a field we accept
/// unconditionally would be pure ceremony. The NTLMSSP signature is an 8-byte
/// magic that cannot appear in the surrounding ASN.1 at this nesting depth, so
/// scanning for it is unambiguous in practice — and its *position* is exactly
/// the signal needed to tell the two framings apart.
fn find_ntlmssp(blob: &[u8]) -> Option<(u32, Framing)> {
    let start = blob
        .windows(NTLMSSP_SIGNATURE.len())
        .position(|w| w == NTLMSSP_SIGNATURE)?;
    let msg = &blob[start..];
    if msg.len() < 12 {
        return None;
    }
    let msg_type = u32::from_le_bytes(msg[8..12].try_into().unwrap());
    let framing = if start == 0 {
        Framing::Raw
    } else {
        Framing::Spnego
    };
    Some((msg_type, framing))
}

/// Build an NTLMSSP CHALLENGE (type 2) message.
///
/// The challenge nonce is random even though nothing verifies the response to
/// it. A fixed nonce would be a gratuitous oddity in a packet capture, and
/// costs nothing to avoid.
fn ntlmssp_challenge(nonce: [u8; 8]) -> Vec<u8> {
    // Flags we assert. EXTENDED_SESSIONSECURITY and TARGET_INFO are what modern
    // clients expect to see; without them macOS falls back to a legacy path.
    const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    const REQUEST_TARGET: u32 = 0x0000_0004;
    const NEGOTIATE_NTLM: u32 = 0x0000_0200;
    const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
    const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
    const EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    const NEGOTIATE_128: u32 = 0x2000_0000;
    const NEGOTIATE_56: u32 = 0x8000_0000;

    let flags = NEGOTIATE_UNICODE
        | REQUEST_TARGET
        | NEGOTIATE_NTLM
        | NEGOTIATE_ALWAYS_SIGN
        | TARGET_TYPE_SERVER
        | EXTENDED_SESSIONSECURITY
        | NEGOTIATE_TARGET_INFO
        | NEGOTIATE_128
        | NEGOTIATE_56;

    let target_name = utf16le(SERVER_NAME);

    // TargetInfo is a list of AV_PAIRs terminated by MsvAvEOL. Two entries plus
    // the terminator is the minimum clients accept.
    let mut target_info = Vec::new();
    for (av_id, value) in [(2u16, &target_name), (1u16, &target_name)] {
        // 2 = MsvAvNbDomainName, 1 = MsvAvNbComputerName
        target_info.extend_from_slice(&av_id.to_le_bytes());
        target_info.extend_from_slice(&(value.len() as u16).to_le_bytes());
        target_info.extend_from_slice(value);
    }
    target_info.extend_from_slice(&0u16.to_le_bytes()); // MsvAvEOL id
    target_info.extend_from_slice(&0u16.to_le_bytes()); // MsvAvEOL length

    // Fixed part is 56 bytes; payload follows.
    const FIXED: usize = 56;
    let target_name_off = FIXED;
    let target_info_off = FIXED + target_name.len();

    let mut w = Writer::with_capacity(FIXED + target_name.len() + target_info.len());
    w.bytes(NTLMSSP_SIGNATURE);
    w.u32(2); // MessageType = CHALLENGE
    w.u16(target_name.len() as u16); // TargetNameLen
    w.u16(target_name.len() as u16); // TargetNameMaxLen
    w.u32(target_name_off as u32);
    w.u32(flags);
    w.bytes(&nonce); // ServerChallenge
    w.zeros(8); // Reserved
    w.u16(target_info.len() as u16); // TargetInfoLen
    w.u16(target_info.len() as u16); // TargetInfoMaxLen
    w.u32(target_info_off as u32);
    w.zeros(8); // Version — zeroed; we do not set NEGOTIATE_VERSION
    w.bytes(&target_name);
    w.bytes(&target_info);
    w.into_vec()
}

/// Per-connection negotiation state.
#[derive(Debug, Default)]
pub(crate) struct SessionState {
    pub(crate) negotiated: bool,
    pub(crate) session_id: u64,
    pub(crate) authenticated: bool,
    /// Tree ids handed out by TREE_CONNECT, mapped to what they point at.
    pub(crate) disk_tree_id: Option<u32>,
    pub(crate) ipc_tree_id: Option<u32>,
    next_tree_id: u32,
}

impl SessionState {
    fn alloc_tree_id(&mut self) -> u32 {
        // Tree id 0 is reserved for "no tree", so start at 1.
        self.next_tree_id += 1;
        self.next_tree_id
    }
}

/// NEGOTIATE (MS-SMB2 2.2.3 request, 2.2.4 response).
///
/// The client sends a list of dialects it supports; we insist on 2.1 being in
/// that list and answer with 2.1 alone. A client that only offers 3.x is
/// refused rather than accommodated.
pub(crate) fn negotiate(
    body: &[u8],
    server_guid: &[u8; 16],
    boot_time: std::time::SystemTime,
    state: &mut SessionState,
) -> Result<Vec<u8>, u32> {
    let mut r = Reader::new(body);
    let structure_size = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
    if structure_size != 36 {
        return Err(status::INVALID_PARAMETER);
    }
    let dialect_count = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
    r.skip(2).map_err(|_| status::INVALID_PARAMETER)?; // SecurityMode
    r.skip(2).map_err(|_| status::INVALID_PARAMETER)?; // Reserved
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // Capabilities
    r.skip(16).map_err(|_| status::INVALID_PARAMETER)?; // ClientGuid
    r.skip(8).map_err(|_| status::INVALID_PARAMETER)?; // ClientStartTime

    let mut offers_2_1 = false;
    for _ in 0..dialect_count {
        let d = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
        if d == DIALECT_SMB_2_1 {
            offers_2_1 = true;
        }
    }
    if !offers_2_1 {
        // MS-SMB2 says to answer a dialect mismatch with NOT_SUPPORTED. On
        // Linux this surfaces as a mount failure naming the dialect, which is
        // the clearest signal we can give that `vers=2.1` is required.
        return Err(status::NOT_SUPPORTED);
    }

    let security_buffer = spnego_neg_token_init();

    let mut w = Writer::with_capacity(64 + security_buffer.len());
    w.u16(65); // StructureSize
    w.u16(SIGNING_ENABLED); // SecurityMode: enabled, never required
    w.u16(DIALECT_SMB_2_1);
    w.u16(0); // NegotiateContextCount (3.1.1 only)
    w.bytes(server_guid);
    w.u32(CAP_LARGE_MTU);
    w.u32(MAX_READ_SIZE); // MaxTransactSize
    w.u32(MAX_READ_SIZE); // MaxReadSize
    w.u32(MAX_READ_SIZE); // MaxWriteSize — advertised, but every WRITE is refused
    w.u64(to_filetime(std::time::SystemTime::now())); // SystemTime
    w.u64(to_filetime(boot_time)); // ServerStartTime
    // Offsets are measured from the start of this response's SMB2 header, and
    // the fixed part of this structure is 64 bytes.
    w.u16((HEADER_LEN + 64) as u16); // SecurityBufferOffset
    w.u16(security_buffer.len() as u16); // SecurityBufferLength
    w.u32(0); // NegotiateContextOffset (3.1.1 only)
    w.bytes(&security_buffer);

    state.negotiated = true;
    Ok(w.into_vec())
}

/// SESSION_SETUP (MS-SMB2 2.2.5 request, 2.2.6 response).
///
/// Two round trips: the client's NTLMSSP NEGOTIATE gets a CHALLENGE back with
/// STATUS_MORE_PROCESSING_REQUIRED, then its AUTHENTICATE is accepted without
/// inspection. Returns `(status, body)` because the first leg is deliberately
/// not a success status.
pub(crate) fn session_setup(
    body: &[u8],
    message: &[u8],
    state: &mut SessionState,
) -> Result<(u32, Vec<u8>), u32> {
    let mut r = Reader::new(body);
    let structure_size = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
    if structure_size != 25 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(1).map_err(|_| status::INVALID_PARAMETER)?; // Flags
    r.skip(1).map_err(|_| status::INVALID_PARAMETER)?; // SecurityMode
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // Capabilities
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // Channel
    let sec_off = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let sec_len = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;

    // Security buffer offsets are relative to the SMB2 header, so they index
    // the whole message rather than the body.
    let msg_reader = Reader::new(message);
    let blob = msg_reader
        .slice_at(sec_off, sec_len)
        .map_err(|_| status::INVALID_PARAMETER)?;

    let (msg_type, framing) = find_ntlmssp(blob).ok_or(status::INVALID_PARAMETER)?;

    let (resp_status, session_flags, token) = match msg_type {
        NTLMSSP_NEGOTIATE => {
            if state.session_id == 0 {
                // Any non-zero value works; the client echoes it back on every
                // later request. Randomised so two servers in one process never
                // hand out the same id.
                state.session_id = u64::from_le_bytes(rand::random::<[u8; 8]>()) | 1;
            }
            let challenge = ntlmssp_challenge(rand::random::<[u8; 8]>());
            let token = match framing {
                Framing::Raw => challenge,
                Framing::Spnego => spnego_challenge(&challenge),
            };
            (status::MORE_PROCESSING_REQUIRED, 0u16, token)
        }
        NTLMSSP_AUTHENTICATE => {
            state.authenticated = true;
            let token = match framing {
                // Raw NTLMSSP has no "accept" message: the exchange ends with
                // the AUTHENTICATE, and the response carries an empty buffer.
                Framing::Raw => Vec::new(),
                Framing::Spnego => spnego_accept(),
            };
            (status::SUCCESS, SESSION_FLAG_IS_GUEST, token)
        }
        _ => return Err(status::INVALID_PARAMETER),
    };

    let mut w = Writer::with_capacity(8 + token.len());
    w.u16(9); // StructureSize
    w.u16(session_flags);
    w.u16((HEADER_LEN + 8) as u16); // SecurityBufferOffset
    w.u16(token.len() as u16); // SecurityBufferLength
    w.bytes(&token);
    Ok((resp_status, w.into_vec()))
}

/// What a connected tree points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeKind {
    /// The snapshot share.
    Disk,
    /// IPC$. Accepted because macOS connects to it during mount, but every
    /// operation on it is refused.
    Ipc,
}

/// TREE_CONNECT (MS-SMB2 2.2.9 request, 2.2.10 response).
///
/// The path is a UNC of the form `\\host\share`; only the last component is
/// meaningful to us.
pub(crate) fn tree_connect(
    body: &[u8],
    message: &[u8],
    share_name: &str,
    state: &mut SessionState,
) -> Result<(Vec<u8>, TreeKind, u32), u32> {
    let mut r = Reader::new(body);
    let structure_size = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
    if structure_size != 9 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(2).map_err(|_| status::INVALID_PARAMETER)?; // Reserved / Flags
    let path_off = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let path_len = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;

    let msg_reader = Reader::new(message);
    let raw = msg_reader
        .slice_at(path_off, path_len)
        .map_err(|_| status::INVALID_PARAMETER)?;
    let path = from_utf16le(raw).map_err(|_| status::OBJECT_PATH_SYNTAX_BAD)?;

    let requested = path.rsplit('\\').next().unwrap_or_default();

    let kind = if requested.eq_ignore_ascii_case(share_name) {
        TreeKind::Disk
    } else if requested.eq_ignore_ascii_case("IPC$") {
        TreeKind::Ipc
    } else {
        return Err(status::BAD_NETWORK_NAME);
    };

    let tree_id = state.alloc_tree_id();
    match kind {
        TreeKind::Disk => state.disk_tree_id = Some(tree_id),
        TreeKind::Ipc => state.ipc_tree_id = Some(tree_id),
    }

    let mut w = Writer::with_capacity(16);
    w.u16(16); // StructureSize
    w.u8(match kind {
        TreeKind::Disk => SHARE_TYPE_DISK,
        TreeKind::Ipc => SHARE_TYPE_PIPE,
    });
    w.u8(0); // Reserved
    w.u32(0); // ShareFlags: manual caching, no DFS, no encryption
    w.u32(0); // Capabilities
    w.u32(match kind {
        // Advertising the read-only mask here is what makes a client show the
        // mount as read-only before it ever attempts a write.
        TreeKind::Disk => access::READ_ONLY,
        TreeKind::Ipc => 0,
    });
    Ok((w.into_vec(), kind, tree_id))
}

/// ECHO, LOGOFF and TREE_DISCONNECT all have the same 4-byte shape:
/// StructureSize followed by a reserved u16.
pub(crate) fn simple_ack() -> Vec<u8> {
    let mut w = Writer::with_capacity(4);
    w.u16(4); // StructureSize
    w.u16(0); // Reserved
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smb::proto::HEADER_LEN;

    // Wrap a body so that message-relative offsets (which count the 64-byte
    // header) line up the way a real request's would.
    fn as_message(body: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; HEADER_LEN];
        m.extend_from_slice(body);
        m
    }

    fn negotiate_request(dialects: &[u16]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(36);
        w.u16(dialects.len() as u16);
        w.u16(0); // SecurityMode
        w.u16(0); // Reserved
        w.u32(0); // Capabilities
        w.zeros(16); // ClientGuid
        w.u64(0); // ClientStartTime
        for d in dialects {
            w.u16(*d);
        }
        w.into_vec()
    }

    #[test]
    fn negotiate_selects_2_1_from_a_multi_dialect_offer() {
        let mut state = SessionState::default();
        let body = negotiate_request(&[0x0202, 0x0210, 0x0300, 0x0302, 0x0311]);
        let resp = negotiate(&body, &[0u8; 16], std::time::SystemTime::now(), &mut state).unwrap();

        let mut r = Reader::new(&resp);
        assert_eq!(r.u16().unwrap(), 65, "StructureSize");
        assert_eq!(r.u16().unwrap(), SIGNING_ENABLED);
        assert_eq!(r.u16().unwrap(), DIALECT_SMB_2_1);
        assert!(state.negotiated);
    }

    #[test]
    fn negotiate_refuses_a_client_that_omits_2_1() {
        let mut state = SessionState::default();
        let body = negotiate_request(&[0x0300, 0x0311]);
        let err =
            negotiate(&body, &[0u8; 16], std::time::SystemTime::now(), &mut state).unwrap_err();
        assert_eq!(err, status::NOT_SUPPORTED);
        assert!(!state.negotiated);
    }

    #[test]
    fn negotiate_response_security_buffer_offset_is_header_relative() {
        let mut state = SessionState::default();
        let body = negotiate_request(&[DIALECT_SMB_2_1]);
        let resp = negotiate(&body, &[0u8; 16], std::time::SystemTime::now(), &mut state).unwrap();

        let off = u16::from_le_bytes(resp[56..58].try_into().unwrap()) as usize;
        let len = u16::from_le_bytes(resp[58..60].try_into().unwrap()) as usize;
        assert_eq!(off, HEADER_LEN + 64, "offset counts the SMB2 header");
        // The buffer sits right after the 64-byte fixed part of the body.
        assert_eq!(&resp[64..64 + len], spnego_neg_token_init().as_slice());
    }

    #[test]
    fn negotiate_rejects_a_bad_structure_size() {
        let mut state = SessionState::default();
        let mut body = negotiate_request(&[DIALECT_SMB_2_1]);
        body[0] = 35;
        assert_eq!(
            negotiate(&body, &[0u8; 16], std::time::SystemTime::now(), &mut state).unwrap_err(),
            status::INVALID_PARAMETER
        );
    }

    #[test]
    fn negotiate_rejects_a_dialect_count_that_overruns_the_body() {
        let mut state = SessionState::default();
        let mut body = negotiate_request(&[DIALECT_SMB_2_1]);
        body[2..4].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            negotiate(&body, &[0u8; 16], std::time::SystemTime::now(), &mut state).unwrap_err(),
            status::INVALID_PARAMETER
        );
    }

    fn session_setup_request(token: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut w = Writer::new();
        w.u16(25);
        w.u8(0); // Flags
        w.u8(0); // SecurityMode
        w.u32(0); // Capabilities
        w.u32(0); // Channel
        w.u16((HEADER_LEN + 24) as u16); // SecurityBufferOffset
        w.u16(token.len() as u16);
        w.u64(0); // PreviousSessionId
        w.bytes(token);
        let body = w.into_vec();
        let message = as_message(&body);
        (body, message)
    }

    fn ntlmssp_message(msg_type: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(NTLMSSP_SIGNATURE);
        v.extend_from_slice(&msg_type.to_le_bytes());
        v.extend_from_slice(&[0u8; 32]);
        v
    }

    #[test]
    fn session_setup_challenges_then_accepts_as_guest() {
        let mut state = SessionState::default();

        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let (st, resp) = session_setup(&body, &message, &mut state).unwrap();
        assert_eq!(st, status::MORE_PROCESSING_REQUIRED);
        assert_ne!(state.session_id, 0, "a session id is assigned on leg one");
        assert!(!state.authenticated);
        let flags = u16::from_le_bytes(resp[2..4].try_into().unwrap());
        assert_eq!(flags, 0, "not a guest until the exchange completes");

        let first_session = state.session_id;
        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_AUTHENTICATE));
        let (st, resp) = session_setup(&body, &message, &mut state).unwrap();
        assert_eq!(st, status::SUCCESS);
        assert!(state.authenticated);
        assert_eq!(state.session_id, first_session, "id is stable across legs");
        let flags = u16::from_le_bytes(resp[2..4].try_into().unwrap());
        assert_eq!(
            flags, SESSION_FLAG_IS_GUEST,
            "guest is what waives signing on the client"
        );
    }

    #[test]
    fn session_setup_rejects_a_blob_with_no_ntlmssp_token() {
        let mut state = SessionState::default();
        let (body, message) = session_setup_request(b"not a token at all");
        assert_eq!(
            session_setup(&body, &message, &mut state).unwrap_err(),
            status::INVALID_PARAMETER
        );
    }

    #[test]
    fn session_setup_rejects_an_unknown_ntlmssp_message_type() {
        let mut state = SessionState::default();
        let (body, message) = session_setup_request(&ntlmssp_message(2));
        assert_eq!(
            session_setup(&body, &message, &mut state).unwrap_err(),
            status::INVALID_PARAMETER
        );
    }

    #[test]
    fn find_ntlmssp_distinguishes_raw_from_spnego_framing() {
        let inner = ntlmssp_message(NTLMSSP_NEGOTIATE);

        let (ty, framing) = find_ntlmssp(&inner).unwrap();
        assert_eq!(ty, NTLMSSP_NEGOTIATE);
        assert_eq!(framing, Framing::Raw, "signature at offset zero is raw");

        let wrapped = spnego_challenge(&inner);
        let (ty, framing) = find_ntlmssp(&wrapped).unwrap();
        assert_eq!(ty, NTLMSSP_NEGOTIATE);
        assert_eq!(framing, Framing::Spnego);
    }

    /// The Linux kernel client with `sec=none` sends raw NTLMSSP and rejects an
    /// SPNEGO-wrapped reply with "blob signature incorrect". The reply framing
    /// must mirror the request's.
    #[test]
    fn session_setup_mirrors_raw_ntlmssp_framing() {
        let mut state = SessionState::default();

        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let (st, resp) = session_setup(&body, &message, &mut state).unwrap();
        assert_eq!(st, status::MORE_PROCESSING_REQUIRED);

        let len = u16::from_le_bytes(resp[6..8].try_into().unwrap()) as usize;
        let token = &resp[8..8 + len];
        assert_eq!(
            &token[..NTLMSSP_SIGNATURE.len()],
            NTLMSSP_SIGNATURE,
            "a raw request must get a raw CHALLENGE back, not a NegTokenResp"
        );

        // The final leg carries no token at all under raw framing.
        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_AUTHENTICATE));
        let (st, resp) = session_setup(&body, &message, &mut state).unwrap();
        assert_eq!(st, status::SUCCESS);
        assert_eq!(u16::from_le_bytes(resp[6..8].try_into().unwrap()), 0);
        assert_eq!(
            u16::from_le_bytes(resp[2..4].try_into().unwrap()),
            SESSION_FLAG_IS_GUEST
        );
    }

    #[test]
    fn session_setup_mirrors_spnego_framing() {
        let mut state = SessionState::default();
        let wrapped = spnego_challenge(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let (body, message) = session_setup_request(&wrapped);
        let (_, resp) = session_setup(&body, &message, &mut state).unwrap();

        let len = u16::from_le_bytes(resp[6..8].try_into().unwrap()) as usize;
        let token = &resp[8..8 + len];
        assert_eq!(token[0], 0xA1, "SPNEGO request must get a NegTokenResp back");
    }

    #[test]
    fn ntlmssp_challenge_payload_offsets_are_in_range() {
        let msg = ntlmssp_challenge([0xAB; 8]);
        let target_name_len = u16::from_le_bytes(msg[12..14].try_into().unwrap()) as usize;
        let target_name_off = u32::from_le_bytes(msg[16..20].try_into().unwrap()) as usize;
        let target_info_len = u16::from_le_bytes(msg[40..42].try_into().unwrap()) as usize;
        let target_info_off = u32::from_le_bytes(msg[44..48].try_into().unwrap()) as usize;

        assert_eq!(target_name_off, 56, "fixed part of a CHALLENGE is 56 bytes");
        assert!(target_name_off + target_name_len <= msg.len());
        assert!(target_info_off + target_info_len <= msg.len());
        assert_eq!(&msg[24..32], &[0xAB; 8], "ServerChallenge nonce");
        assert_eq!(
            from_utf16le(&msg[target_name_off..target_name_off + target_name_len]).unwrap(),
            SERVER_NAME
        );
        // TargetInfo must end with the MsvAvEOL pair.
        let info_end = target_info_off + target_info_len;
        assert_eq!(&msg[info_end - 4..info_end], &[0, 0, 0, 0]);
    }

    fn tree_connect_request(path: &str) -> (Vec<u8>, Vec<u8>) {
        let encoded = utf16le(path);
        let mut w = Writer::new();
        w.u16(9);
        w.u16(0); // Reserved
        w.u16((HEADER_LEN + 8) as u16); // PathOffset
        w.u16(encoded.len() as u16);
        w.bytes(&encoded);
        let body = w.into_vec();
        let message = as_message(&body);
        (body, message)
    }

    #[test]
    fn tree_connect_accepts_the_share_case_insensitively() {
        let mut state = SessionState::default();
        let (body, message) = tree_connect_request(r"\\127.0.0.1\SNAP");
        let (resp, kind, tree_id) = tree_connect(&body, &message, "snap", &mut state).unwrap();
        assert_eq!(kind, TreeKind::Disk);
        assert_ne!(tree_id, 0, "tree id 0 means no tree");
        assert_eq!(state.disk_tree_id, Some(tree_id));

        assert_eq!(u16::from_le_bytes(resp[0..2].try_into().unwrap()), 16);
        assert_eq!(resp[2], SHARE_TYPE_DISK);
        let maximal = u32::from_le_bytes(resp[12..16].try_into().unwrap());
        assert_eq!(maximal, access::READ_ONLY);
        assert_eq!(maximal & access::WRITE_BITS, 0);
    }

    #[test]
    fn tree_connect_accepts_ipc_as_a_pipe_share() {
        let mut state = SessionState::default();
        let (body, message) = tree_connect_request(r"\\127.0.0.1\IPC$");
        let (resp, kind, tree_id) = tree_connect(&body, &message, "snap", &mut state).unwrap();
        assert_eq!(kind, TreeKind::Ipc);
        assert_eq!(resp[2], SHARE_TYPE_PIPE);
        assert_eq!(state.ipc_tree_id, Some(tree_id));
        assert_eq!(u32::from_le_bytes(resp[12..16].try_into().unwrap()), 0);
    }

    #[test]
    fn tree_connect_refuses_an_unknown_share() {
        let mut state = SessionState::default();
        let (body, message) = tree_connect_request(r"\\127.0.0.1\secrets");
        assert_eq!(
            tree_connect(&body, &message, "snap", &mut state).unwrap_err(),
            status::BAD_NETWORK_NAME
        );
    }

    #[test]
    fn tree_connect_hands_out_distinct_tree_ids() {
        let mut state = SessionState::default();
        let (b1, m1) = tree_connect_request(r"\\127.0.0.1\snap");
        let (_, _, first) = tree_connect(&b1, &m1, "snap", &mut state).unwrap();
        let (b2, m2) = tree_connect_request(r"\\127.0.0.1\IPC$");
        let (_, _, second) = tree_connect(&b2, &m2, "snap", &mut state).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn spnego_tokens_are_well_formed_der() {
        let init = spnego_neg_token_init();
        assert_eq!(init[0], 0x60, "NegTokenInit is APPLICATION 0");
        assert!(
            init.windows(OID_NTLMSSP.len()).any(|w| w == OID_NTLMSSP),
            "the mech list must advertise NTLMSSP"
        );

        let accept = spnego_accept();
        assert_eq!(accept[0], 0xA1, "NegTokenResp is context 1");
        // negState accept-completed is ENUMERATED 0.
        assert!(accept.windows(3).any(|w| w == [0x0A, 0x01, 0x00]));
    }

    #[test]
    fn simple_ack_is_the_four_byte_shape() {
        assert_eq!(simple_ack(), vec![4, 0, 0, 0]);
    }
}
