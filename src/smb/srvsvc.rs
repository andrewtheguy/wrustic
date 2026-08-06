// Share enumeration, so the share can be *browsed* and not only addressed.
//
// Without this, a client that knows the full path works fine — `\\host\snap`,
// `smb://host/snap` — but a client asked to list what a server offers gets
// nothing. In Explorer that is typing `\\host\` and getting an error after a
// long wait; in Finder it is connecting to `smb://host` and being shown no
// share to pick, leaving the user to navigate to the mount point by hand.
//
// Both go through the same mechanism: the client connects to the IPC$ tree,
// opens the well-known `srvsvc` named pipe, and makes a DCE/RPC call to
// NetrShareEnum. wrustic previously accepted the IPC$ tree (macOS connects to
// it during mount) but answered NOT_SUPPORTED to every command on it, so the
// pipe could never be opened.
//
// Scope, deliberately narrow: one interface (SRVSVC), one operation
// (NetrShareEnum, opnum 15), one info level (1). Everything else — every other
// opnum, every other interface — gets a DCE/RPC fault, which is a well-formed
// "no" that clients handle. This is not an RPC stack; it is the smallest thing
// that answers "what shares do you have?" truthfully.
//
// The read-only guarantee is preserved. `WRITE` remains
// MEDIA_WRITE_PROTECTED everywhere except a handle that is this pipe on an
// IPC$ tree, where it writes into a bounded in-memory buffer and never touches
// the snapshot. There is still no code path that could modify repository data.

use super::proto::status;
use super::wire::{Reader, Writer, from_utf16le, utf16le};

/// The file id the srvsvc pipe is opened as.
///
/// A fixed sentinel rather than an entry in `Handles`: that table is built
/// around snapshot files (paths, readers, directory cursors), none of which a
/// pipe has, and a connection can hold at most one IPC$ tree and therefore at
/// most one of these. Chosen far above anything `Handles` allocates — it counts
/// up from 1 — and clear of the `u64::MAX` compound placeholder.
pub(crate) const PIPE_FILE_ID: u64 = 0xFFFF_FFFF_FFFF_FFFE;

/// The pipe name clients open for share enumeration.
const PIPE_NAME: &str = "srvsvc";

/// Cap on a buffered DCE/RPC request. Real ones are a few hundred bytes; this
/// exists so a client cannot make the server hold memory by writing forever.
const MAX_REQUEST: usize = 64 * 1024;

/// What the server advertises it can send and receive in one fragment. Ours are
/// far smaller, but clients size their own buffers from these.
const MAX_FRAG: u16 = 4280;

mod ptype {
    pub(super) const REQUEST: u8 = 0;
    pub(super) const RESPONSE: u8 = 2;
    pub(super) const FAULT: u8 = 3;
    pub(super) const BIND: u8 = 11;
    pub(super) const BIND_ACK: u8 = 12;
    pub(super) const ALTER_CONTEXT: u8 = 14;
    pub(super) const ALTER_CONTEXT_RESP: u8 = 15;
}

/// PFC_FIRST_FRAG | PFC_LAST_FRAG. Every PDU here is a complete message.
const PFC_FIRST_LAST: u8 = 0x03;

/// NDR transfer syntax, 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0, in the
/// little-endian layout DCE/RPC puts on the wire.
const NDR_SYNTAX: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
const NDR_SYNTAX_VERSION: u32 = 2;

/// NetrShareEnum. The only operation implemented.
const OPNUM_NET_SHARE_ENUM: u16 = 15;

/// STYPE_DISKTREE — an ordinary file share.
const STYPE_DISKTREE: u32 = 0;

/// Win32 error codes returned in the NET_API_STATUS trailer.
const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_LEVEL: u32 = 124;

/// DCE/RPC fault code for an opnum the interface does not implement.
const NCA_S_OP_RNG_ERROR: u32 = 0x1C01_0002;

/// State for one open srvsvc pipe.
#[derive(Default)]
pub(crate) struct Pipe {
    /// Response bytes waiting to be collected by a READ. A DCE/RPC exchange is
    /// strictly request-then-response, so at most one reply is ever pending.
    pending: Vec<u8>,
}

/// CREATE on the IPC$ tree.
///
/// Only `srvsvc` opens. Any other pipe name is reported as not found rather
/// than not supported, which is what a server with no such pipe would say.
pub(crate) fn create(
    body: &[u8],
    message: &[u8],
    pipe: &mut Option<Pipe>,
) -> Result<Vec<u8>, u32> {
    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 57 {
        return Err(status::INVALID_PARAMETER);
    }
    // Everything up to the name offset is irrelevant for a pipe: there is no
    // path to resolve, no disposition that means anything, and no attributes.
    r.skip(2 + 4 + 8 + 8).map_err(|_| status::INVALID_PARAMETER)?;
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // DesiredAccess
    r.skip(4 + 4 + 4 + 4).map_err(|_| status::INVALID_PARAMETER)?;
    let name_off = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let name_len = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;

    let msg = Reader::new(message);
    let raw = msg
        .slice_at(name_off, name_len)
        .map_err(|_| status::INVALID_PARAMETER)?;
    let name = from_utf16le(raw).map_err(|_| status::OBJECT_NAME_NOT_FOUND)?;
    if !name.eq_ignore_ascii_case(PIPE_NAME) {
        return Err(status::OBJECT_NAME_NOT_FOUND);
    }

    *pipe = Some(Pipe::default());

    let mut w = Writer::with_capacity(89);
    w.u16(89); // StructureSize
    w.u8(0); // OplockLevel
    w.u8(0); // Flags
    w.u32(1); // CreateAction — FILE_OPENED
    // A pipe has no meaningful timestamps or size. Zeros are what a server
    // reports for one, and no client uses them for anything.
    w.u64(0); // CreationTime
    w.u64(0); // LastAccessTime
    w.u64(0); // LastWriteTime
    w.u64(0); // ChangeTime
    w.u64(0); // AllocationSize
    w.u64(0); // EndOfFile
    w.u32(0x0000_0080); // FileAttributes — FILE_ATTRIBUTE_NORMAL
    w.u32(0); // Reserved2
    w.u64(PIPE_FILE_ID); // FileId, persistent
    w.u64(PIPE_FILE_ID); // FileId, volatile
    w.u32(0); // CreateContextsOffset
    w.u32(0); // CreateContextsLength
    Ok(w.into_vec())
}

/// CLOSE on the pipe.
pub(crate) fn close(pipe: &mut Option<Pipe>) -> Result<Vec<u8>, u32> {
    if pipe.take().is_none() {
        return Err(status::FILE_CLOSED);
    }
    let mut w = Writer::with_capacity(60);
    w.u16(60); // StructureSize
    w.u16(0); // Flags
    w.u32(0); // Reserved
    w.zeros(8 * 6 + 4 + 4); // times, sizes, attributes, reserved — all zero
    Ok(w.into_vec())
}

/// WRITE on the pipe: the client handing over a DCE/RPC request.
///
/// This is the one write wrustic accepts anywhere, and it lands in
/// `Pipe::pending` — an in-memory buffer bounded by `MAX_REQUEST`. It cannot
/// reach a snapshot: the caller only routes here for a handle that is this pipe
/// on an IPC$ tree.
pub(crate) fn write(
    body: &[u8],
    message: &[u8],
    pipe: &mut Option<Pipe>,
    share_name: &str,
) -> Result<Vec<u8>, u32> {
    let pipe = pipe.as_mut().ok_or(status::FILE_CLOSED)?;

    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 49 {
        return Err(status::INVALID_PARAMETER);
    }
    let data_off = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let length = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;
    if length > MAX_REQUEST {
        return Err(status::INVALID_PARAMETER);
    }

    let msg = Reader::new(message);
    let data = msg
        .slice_at(data_off, length)
        .map_err(|_| status::INVALID_PARAMETER)?;
    pipe.pending = dispatch(data, share_name);

    let mut w = Writer::with_capacity(17);
    w.u16(17); // StructureSize
    w.u16(0); // Reserved
    w.u32(length as u32); // Count — the whole request was consumed
    w.u32(0); // Remaining
    w.u16(0); // WriteChannelInfoOffset
    w.u16(0); // WriteChannelInfoLength
    Ok(w.into_vec())
}

/// READ on the pipe: the client collecting the response its WRITE produced.
pub(crate) fn read(body: &[u8], pipe: &mut Option<Pipe>) -> Result<Vec<u8>, u32> {
    let pipe = pipe.as_mut().ok_or(status::FILE_CLOSED)?;

    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 49 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(1 + 1).map_err(|_| status::INVALID_PARAMETER)?; // Padding, Flags
    let length = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;

    if pipe.pending.is_empty() {
        // Nothing was asked, so there is nothing to collect. END_OF_FILE is how
        // a read past the end of a pipe's queued data is reported.
        return Err(status::END_OF_FILE);
    }
    let take = length.min(pipe.pending.len());
    let data: Vec<u8> = pipe.pending.drain(..take).collect();

    let mut w = Writer::with_capacity(16 + data.len());
    w.u16(17); // StructureSize
    w.u8((super::HEADER_LEN + 16) as u8); // DataOffset
    w.u8(0); // Reserved
    w.u32(data.len() as u32); // DataLength
    w.u32(pipe.pending.len() as u32); // DataRemaining
    w.u32(0); // Reserved2
    w.bytes(&data);
    Ok(w.into_vec())
}

/// FSCTL_PIPE_TRANSCEIVE — write and read in one round trip.
///
/// What Windows actually uses for RPC over a pipe; the separate WRITE/READ pair
/// above is what other clients do. Both have to work.
pub(crate) fn transceive(
    body: &[u8],
    message: &[u8],
    pipe: &mut Option<Pipe>,
    share_name: &str,
) -> Result<Vec<u8>, u32> {
    /// FSCTL_PIPE_TRANSCEIVE (MS-SMB2 2.2.31).
    const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;

    let pipe_state = pipe.as_mut().ok_or(status::FILE_CLOSED)?;

    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 57 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(2).map_err(|_| status::INVALID_PARAMETER)?; // Reserved
    let ctl_code = r.u32().map_err(|_| status::INVALID_PARAMETER)?;
    if ctl_code != FSCTL_PIPE_TRANSCEIVE {
        // Every other FSCTL stays refused, as it always was.
        return Err(status::NOT_SUPPORTED);
    }
    r.skip(16).map_err(|_| status::INVALID_PARAMETER)?; // FileId
    let input_off = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let input_len = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;
    if input_len > MAX_REQUEST {
        return Err(status::INVALID_PARAMETER);
    }

    let msg = Reader::new(message);
    let input = msg
        .slice_at(input_off, input_len)
        .map_err(|_| status::INVALID_PARAMETER)?;
    let output = dispatch(input, share_name);
    pipe_state.pending.clear();

    // OutputOffset counts from the start of the SMB2 header, and the output
    // follows the 48-byte IOCTL response body.
    let output_off = (super::HEADER_LEN + 48) as u32;
    let mut w = Writer::with_capacity(48 + output.len());
    w.u16(49); // StructureSize
    w.u16(0); // Reserved
    w.u32(ctl_code);
    w.u64(PIPE_FILE_ID); // FileId, persistent
    w.u64(PIPE_FILE_ID); // FileId, volatile
    w.u32(0); // InputOffset — no input is echoed back, so it points nowhere
    w.u32(0); // InputCount
    w.u32(output_off); // OutputOffset
    w.u32(output.len() as u32); // OutputCount
    w.u32(0); // Flags
    w.u32(0); // Reserved2
    w.bytes(&output);
    Ok(w.into_vec())
}

// ---------------------------------------------------------------------------
// DCE/RPC
// ---------------------------------------------------------------------------

/// Turn one DCE/RPC PDU into its reply.
///
/// Never fails: an unparseable or unsupported request becomes a fault, because
/// a client that gets a well-formed "no" moves on, while one that gets silence
/// or a dropped connection retries and stalls.
fn dispatch(request: &[u8], share_name: &str) -> Vec<u8> {
    let Some(hdr) = PduHeader::parse(request) else {
        return fault(0, NCA_S_OP_RNG_ERROR);
    };
    match hdr.ptype {
        ptype::BIND => bind_ack(&hdr, ptype::BIND_ACK),
        ptype::ALTER_CONTEXT => bind_ack(&hdr, ptype::ALTER_CONTEXT_RESP),
        ptype::REQUEST => {
            // Request body: alloc_hint (4), context_id (2), opnum (2).
            let Some(stub) = request.get(16..) else {
                return fault(hdr.call_id, NCA_S_OP_RNG_ERROR);
            };
            if stub.len() < 8 {
                return fault(hdr.call_id, NCA_S_OP_RNG_ERROR);
            }
            let opnum = u16::from_le_bytes([stub[6], stub[7]]);
            if opnum != OPNUM_NET_SHARE_ENUM {
                return fault(hdr.call_id, NCA_S_OP_RNG_ERROR);
            }
            let level = requested_level(&stub[8..]);
            response(hdr.call_id, &net_share_enum(share_name, level))
        }
        _ => fault(hdr.call_id, NCA_S_OP_RNG_ERROR),
    }
}

struct PduHeader {
    ptype: u8,
    call_id: u32,
}

impl PduHeader {
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 || buf[0] != 5 {
            return None;
        }
        // frag_length must describe exactly this buffer. Shorter means
        // trailing bytes that would be silently ignored; longer means a
        // fragment of a larger PDU, which this server does not reassemble.
        // Either way the input is not the single complete PDU the dispatcher
        // assumes, so it faults rather than guesses.
        let frag_length = u16::from_le_bytes([buf[8], buf[9]]) as usize;
        if frag_length != buf.len() {
            return None;
        }
        Some(Self {
            ptype: buf[2],
            call_id: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        })
    }
}

fn write_pdu_header(w: &mut Writer, ptype: u8, frag_len: u16, call_id: u32) {
    w.u8(5); // rpc_vers
    w.u8(0); // rpc_vers_minor
    w.u8(ptype);
    w.u8(PFC_FIRST_LAST);
    // Data representation: little-endian integers, ASCII characters, IEEE
    // floats. The only combination anything on this path uses.
    w.bytes(&[0x10, 0x00, 0x00, 0x00]);
    w.u16(frag_len);
    w.u16(0); // auth_length
    w.u32(call_id);
}

/// BIND_ACK / ALTER_CONTEXT_RESP.
///
/// The presented abstract syntax is accepted without inspection: this pipe
/// serves exactly one interface, so a client that bound to something else will
/// fault on its first call anyway, which is a clearer failure than a bind_nak.
fn bind_ack(hdr: &PduHeader, ptype: u8) -> Vec<u8> {
    let sec_addr = b"\\PIPE\\srvsvc\0";

    let mut body = Writer::new();
    body.u16(MAX_FRAG); // max_xmit_frag
    body.u16(MAX_FRAG); // max_recv_frag
    body.u32(0x0000_1063); // assoc_group_id — any non-zero value
    body.u16(sec_addr.len() as u16);
    body.bytes(sec_addr);
    // The results list is 4-byte aligned from the start of the PDU. The header
    // is 16 bytes, so aligning the body is equivalent.
    body.align_to(4);
    body.u8(1); // num_results
    body.zeros(3); // reserved
    body.u16(0); // result — acceptance
    body.u16(0); // reason
    body.bytes(&NDR_SYNTAX);
    body.u32(NDR_SYNTAX_VERSION);

    let body = body.into_vec();
    let mut w = Writer::with_capacity(16 + body.len());
    write_pdu_header(&mut w, ptype, (16 + body.len()) as u16, hdr.call_id);
    w.bytes(&body);
    w.into_vec()
}

fn response(call_id: u32, stub: &[u8]) -> Vec<u8> {
    let mut w = Writer::with_capacity(24 + stub.len());
    write_pdu_header(&mut w, ptype::RESPONSE, (24 + stub.len()) as u16, call_id);
    w.u32(stub.len() as u32); // alloc_hint
    w.u16(0); // context_id
    w.u8(0); // cancel_count
    w.u8(0); // reserved
    w.bytes(stub);
    w.into_vec()
}

fn fault(call_id: u32, code: u32) -> Vec<u8> {
    let mut w = Writer::with_capacity(32);
    write_pdu_header(&mut w, ptype::FAULT, 32, call_id);
    w.u32(0); // alloc_hint
    w.u16(0); // context_id
    w.u8(0); // cancel_count
    w.u8(0); // reserved
    w.u32(code); // status
    w.u32(0); // reserved2
    w.into_vec()
}

// ---------------------------------------------------------------------------
// NetrShareEnum, NDR-encoded
// ---------------------------------------------------------------------------

/// Pull the requested info level out of a NetrShareEnum request.
///
/// The stub starts with a `[unique]` ServerName string, and skipping it
/// correctly means walking a conformant varying string. Rather than parse
/// something no answer depends on, look for the level in the two places it can
/// sit — immediately after a NULL ServerName, or after the string that follows
/// a non-NULL one — and fall back to level 1, which is what every client that
/// enumerates shares actually asks for.
fn requested_level(stub: &[u8]) -> u32 {
    let u32_at = |off: usize| -> Option<u32> {
        let b = stub.get(off..off + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let Some(server_ptr) = u32_at(0) else {
        return 1;
    };
    if server_ptr == 0 {
        // NULL ServerName: the level follows immediately.
        return u32_at(4).unwrap_or(1);
    }
    // Non-NULL: max_count, offset, actual_count, then actual_count UTF-16
    // characters padded to a 4-byte boundary.
    let Some(actual) = u32_at(12) else { return 1 };
    let chars = (actual as usize).saturating_mul(2);
    let padded = chars.div_ceil(4) * 4;
    u32_at(16 + padded).unwrap_or(1)
}

/// Encode the NetrShareEnum reply listing the one share this server offers.
///
/// Only level 1 (name, type, remark) is produced. A client asking for another
/// level gets a well-formed reply carrying ERROR_INVALID_LEVEL and a NULL
/// container, which is the documented way to say so.
fn net_share_enum(share_name: &str, level: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(level); // SHARE_ENUM_STRUCT.Level
    w.u32(level); // union discriminant

    if level != 1 {
        w.u32(0); // NULL container
        w.u32(0); // TotalEntries
        w.u32(0); // ResumeHandle — NULL
        w.u32(ERROR_INVALID_LEVEL);
        return w.into_vec();
    }

    // Referent ids only have to be non-zero and distinct within the reply.
    w.u32(0x0002_0000); // container pointer
    w.u32(1); // EntriesRead
    w.u32(0x0002_0004); // array pointer
    w.u32(1); // conformant array max_count

    // Entry headers first, then the strings they point at, deferred in the same
    // order — that split is what NDR requires and what a client relies on.
    w.u32(0x0002_0008); // netname pointer
    w.u32(STYPE_DISKTREE);
    w.u32(0x0002_000c); // remark pointer

    ndr_string(&mut w, share_name);
    // A remark is required to be present but may be empty; nothing useful can
    // be said about a snapshot share that its name does not already say.
    ndr_string(&mut w, "");

    w.u32(1); // TotalEntries
    // ResumeHandle returned as NULL: every share is in this one reply, so there
    // is nothing for a client to resume from.
    w.u32(0);
    w.u32(ERROR_SUCCESS);
    w.into_vec()
}

/// A conformant, varying, NUL-terminated NDR string.
fn ndr_string(w: &mut Writer, s: &str) {
    let mut units = utf16le(s);
    units.extend_from_slice(&[0, 0]); // NUL terminator, counted below
    let chars = (units.len() / 2) as u32;
    w.u32(chars); // max_count
    w.u32(0); // offset
    w.u32(chars); // actual_count
    w.bytes(&units);
    w.align_to(4);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stamp the real frag_length into a finished PDU. The fixtures only know
    /// their length once the body is built, and `parse` rejects a PDU whose
    /// frag_length does not match the bytes delivered.
    fn seal(mut pdu: Vec<u8>) -> Vec<u8> {
        let len = pdu.len() as u16;
        pdu[8..10].copy_from_slice(&len.to_le_bytes());
        pdu
    }

    fn bind_pdu(call_id: u32) -> Vec<u8> {
        let mut w = Writer::new();
        write_pdu_header(&mut w, ptype::BIND, 0, call_id);
        w.u16(MAX_FRAG);
        w.u16(MAX_FRAG);
        w.u32(0);
        w.u8(1);
        w.zeros(3);
        w.u16(0);
        w.u8(1);
        w.u8(0);
        w.zeros(20); // abstract syntax
        w.bytes(&NDR_SYNTAX);
        w.u32(NDR_SYNTAX_VERSION);
        seal(w.into_vec())
    }

    fn enum_request(call_id: u32, level: u32) -> Vec<u8> {
        let mut w = Writer::new();
        write_pdu_header(&mut w, ptype::REQUEST, 0, call_id);
        w.u32(0); // alloc_hint
        w.u16(0); // context_id
        w.u16(OPNUM_NET_SHARE_ENUM);
        w.u32(0); // NULL ServerName
        w.u32(level);
        seal(w.into_vec())
    }

    #[test]
    fn bind_is_accepted_and_echoes_the_call_id() {
        let reply = dispatch(&bind_pdu(0x1234), "snap");
        assert_eq!(reply[2], ptype::BIND_ACK);
        assert_eq!(&reply[12..16], &0x1234u32.to_le_bytes());
        // frag_length must describe the whole PDU, or the client waits for more.
        assert_eq!(
            u16::from_le_bytes([reply[8], reply[9]]) as usize,
            reply.len()
        );
        // The accepted transfer syntax has to come back, or the bind is useless.
        assert!(
            reply.windows(16).any(|w| w == NDR_SYNTAX),
            "bind_ack must echo the NDR transfer syntax"
        );
    }

    #[test]
    fn enumeration_lists_the_share_by_name() {
        let reply = dispatch(&enum_request(7, 1), "snap");
        assert_eq!(reply[2], ptype::RESPONSE);
        assert_eq!(
            u16::from_le_bytes([reply[8], reply[9]]) as usize,
            reply.len()
        );

        let stub = &reply[24..];
        assert_eq!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 1); // Level
        assert_eq!(u32::from_le_bytes(stub[12..16].try_into().unwrap()), 1); // EntriesRead
        // The name has to survive as UTF-16, since that is what a client shows.
        let wanted = utf16le("snap");
        assert!(
            stub.windows(wanted.len()).any(|w| w == wanted),
            "share name missing from the reply"
        );
        // Trailing NET_API_STATUS must be success, or the client discards it all.
        let tail = u32::from_le_bytes(stub[stub.len() - 4..].try_into().unwrap());
        assert_eq!(tail, ERROR_SUCCESS);
    }

    /// The share name is whatever the server is serving, not a constant — a
    /// hardcoded "snap" here would list a share that does not exist if the name
    /// ever became configurable.
    #[test]
    fn enumeration_reports_the_configured_share_name() {
        let reply = dispatch(&enum_request(1, 1), "backup-2024");
        let wanted = utf16le("backup-2024");
        assert!(reply.windows(wanted.len()).any(|w| w == wanted));
    }

    /// An unsupported level must still produce a parseable reply carrying the
    /// error, not a fault: a client that asked for level 2 should learn the
    /// level is wrong, not that the call does not exist.
    #[test]
    fn an_unsupported_level_reports_invalid_level() {
        let reply = dispatch(&enum_request(2, 502), "snap");
        assert_eq!(reply[2], ptype::RESPONSE);
        let stub = &reply[24..];
        assert_eq!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 502);
        assert_eq!(u32::from_le_bytes(stub[8..12].try_into().unwrap()), 0); // NULL container
        let tail = u32::from_le_bytes(stub[stub.len() - 4..].try_into().unwrap());
        assert_eq!(tail, ERROR_INVALID_LEVEL);
    }

    /// Everything outside the one implemented operation gets a fault, which is
    /// a "no" the client can act on rather than a hang.
    #[test]
    fn other_opnums_fault() {
        let mut req = enum_request(3, 1);
        // opnum sits at offset 22, right after alloc_hint and context_id.
        req[22..24].copy_from_slice(&16u16.to_le_bytes()); // NetrShareGetInfo
        let reply = dispatch(&req, "snap");
        assert_eq!(reply[2], ptype::FAULT);
        assert_eq!(
            u32::from_le_bytes(reply[24..28].try_into().unwrap()),
            NCA_S_OP_RNG_ERROR
        );
    }

    #[test]
    fn a_malformed_pdu_faults_rather_than_panicking() {
        for junk in [vec![], vec![0u8; 4], vec![9u8; 32], vec![5, 0, 0, 3]] {
            let reply = dispatch(&junk, "snap");
            assert_eq!(reply[2], ptype::FAULT, "junk {junk:?} must fault");
        }
    }

    /// A frag_length that does not match the delivered bytes is either a
    /// malformed PDU or a fragment of a larger one; both are refused, since
    /// nothing here reassembles fragments.
    #[test]
    fn a_wrong_frag_length_faults() {
        // Claims zero.
        let mut req = enum_request(4, 1);
        req[8..10].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(dispatch(&req, "snap")[2], ptype::FAULT);

        // Claims more than was delivered.
        let mut req = enum_request(5, 1);
        let claim = ((req.len() + 4) as u16).to_le_bytes();
        req[8..10].copy_from_slice(&claim);
        assert_eq!(dispatch(&req, "snap")[2], ptype::FAULT);

        // Claims less: the trailing bytes would be silently dropped.
        let mut req = enum_request(6, 1);
        let claim = ((req.len() - 4) as u16).to_le_bytes();
        req[8..10].copy_from_slice(&claim);
        assert_eq!(dispatch(&req, "snap")[2], ptype::FAULT);
    }

    /// The level is read from the request, and a non-NULL ServerName shifts
    /// where it sits — get that wrong and every enumeration silently answers
    /// the wrong level.
    #[test]
    fn level_is_found_past_a_non_null_server_name() {
        // `\\host` is 6 characters, and the counts include the NUL terminator,
        // so both are 7 — declaring 6 while writing 7 units is exactly the kind
        // of drift that puts the level in the wrong place.
        let name = "\\\\host";
        let units = (name.chars().count() + 1) as u32;
        let mut w = Writer::new();
        w.u32(0x0002_0000); // non-NULL ServerName referent
        w.u32(units); // max_count
        w.u32(0); // offset
        w.u32(units); // actual_count
        w.bytes(&utf16le(name));
        w.bytes(&[0, 0]);
        w.align_to(4);
        w.u32(1); // Level
        assert_eq!(requested_level(&w.into_vec()), 1);

        // An even-length name lands the string on a 4-byte boundary with no
        // padding, which is the other half of the arithmetic.
        let name = "\\\\hosts";
        let units = (name.chars().count() + 1) as u32;
        let mut w = Writer::new();
        w.u32(0x0002_0000);
        w.u32(units);
        w.u32(0);
        w.u32(units);
        w.bytes(&utf16le(name));
        w.bytes(&[0, 0]);
        w.align_to(4);
        w.u32(2); // a different level, so a wrong offset cannot pass by luck
        assert_eq!(requested_level(&w.into_vec()), 2);
    }

    /// NDR strings are 4-byte aligned; a missing pad shifts everything after it
    /// and the client reads garbage.
    #[test]
    fn ndr_strings_are_padded_to_four_bytes() {
        for name in ["a", "ab", "abc", "abcd", "snap"] {
            let mut w = Writer::new();
            ndr_string(&mut w, name);
            let out = w.into_vec();
            assert_eq!(out.len() % 4, 0, "{name} left the stream unaligned");
            let actual = u32::from_le_bytes(out[8..12].try_into().unwrap());
            assert_eq!(actual as usize, name.chars().count() + 1, "{name}");
        }
    }
}
