//! `skep deposit`, the nineteenth command: a board's endpoint (REG-1.9).
//!
//! A registered board's node account tells the registry where its board
//! is by one record in its own doc 1: the endpoint, an ordered list of the
//! board's origins. This command deposits it. `--account` names the node
//! account, as `bind` takes one, on the board that account is on
//! (`--board`: the registry's); each `--origin` names an origin the board
//! answers at, in the order a reader tries them (REG-3.34) — each written
//! as given, a canonical origin, and none dialed: whether a reader admits
//! one is the reader's check.
//!
//! The session is the command's own and the node account's: the principal
//! the board seats at `--account` — `--principal`, where given, must be
//! that one — and the selected signing key (the file `--key` or `SKEP_KEY`
//! names, else the store's), content-scoped, as `skep session` opens its,
//! and closed on every exit: an endpoint is no credential. The key is one
//! of the node account's own set — the board owner's, never the service
//! that hosts the board, which holds no such key and signs nothing
//! (REG-4.120). The board judges the record's `sig` under that set.
//!
//! The order is REG-1.51's. The account's home is read first, as a guest,
//! by the metadata read in its three arms (REG-1.52): no document, and
//! this session mints it, born published; a published home, and the run
//! resumes at the deposit; a draft home, and the run halts naming its act
//! before any session opens. The mint is the first signed session's first
//! state alone (`first_session::mint_home`). The setup act beside it, the
//! account's agent space (AUTH-5.87), is `bind`'s to run at the landing:
//! it delegates an address and writes a line in the key store, which a
//! deposit does not, and each state resumes by its own read. Then the
//! endpoint (`registry_record::deposit_endpoint`): the deposit current in
//! the home is read on the audit view and named in `replaces`, none on the
//! account's first, so a reader honors this one as current (REG-1.10) and
//! the one it replaces stays in the home, read as replaced.
//!
//! Stdout carries the deposit's address, `endpoint <link>`, and under it
//! `replaces <link>` where it names one; stderr what was done. A line that
//! names no account or no origin, or names one that does not read, is a
//! usage refusal, exit 2, before any socket opens; the board's refusal is
//! exit 1, a halt exit 3. No person door: the command runs without a
//! terminal.

use skep_client::board::{Board, Scope};
use skep_client::ceremony::first_session::{mint_home, FirstSessionReads};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::ceremony::registry_record::{deposit_endpoint, EndpointDeposit};
use skep_client::derive::principal_of;
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::Halt;
use skep_client::sign::Signer;
use skep_client::store::{KeySelector, KeyStore, Purpose};
use skep_client::Origin;

use super::{board_of, clipped, data, key_named, select_key, store_of, talk, Stop};
use crate::args::{CommandLine, Usage};

/// What the line asks: the node account and the board's origins.
struct Asked {
    /// `--account`: the node account, on the board `--board` names.
    account: String,
    /// Each `--origin`, in the order given, as its canonical spelling.
    origins: Vec<String>,
}

impl Asked {
    /// Reads the line's own flags whole, before any socket opens.
    ///
    /// # Errors
    ///
    /// In this order: no `--account`; an `--account` that is no address;
    /// no `--origin`; the first `--origin` that is no canonical origin, in
    /// `--board`'s own words.
    fn of(c: &CommandLine) -> Result<Asked, Usage> {
        let Some(account) = c.value("--account") else {
            return Err(Usage("--account <address> is required: the node account the endpoint is deposited at".into()));
        };
        if !skep_client::address::is_address_text(account) {
            return Err(Usage(format!("--account: '{}' is not an address (the wire's dotted spelling)", clipped(account))));
        }
        if c.values("--origin").is_empty() {
            return Err(Usage(
                "--origin <origin> is required: the origin your board answers at; repeat it for each further one, in the order a reader tries them".into(),
            ));
        }
        let origins = c
            .values("--origin")
            .iter()
            .map(|text| text.parse::<Origin>().map(|origin| origin.as_str().to_string()).map_err(|e| Usage(format!("--origin: '{text}' is {e}"))))
            .collect::<Result<Vec<String>, Usage>>()?;
        Ok(Asked { account: account.to_string(), origins })
    }
}

pub fn deposit(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    let Asked { account, origins } = Asked::of(c)?;
    // The plaintext non-loopback warning, ahead of everything a signed
    // session needs (AUTH-4.53; §9 item 23: a warning, never a refusal).
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    // The principal is the one the board seats at the account (AUTH-6.37):
    // a deposit lands in that account's doc 1, which its own session alone
    // writes, so a principal given beside it names that one or nothing.
    let Some(principal) = principal_of(&board, &account)? else {
        return Err(Halt::face(
            format!("{account} is not an account on this board"),
            format!("`effective_owner({account})` answers no seat there: an endpoint is deposited at a node account, on the board that account is on"),
            "check --account, and that --board (or SKEP_BOARD) names the board the account is on — the registry's",
        )
        .into());
    };
    if let Some(named) = given.filter(|named| *named != principal) {
        return Err(Halt::face(
            format!("principal {named} is not the principal seated at {account}"),
            format!("the board seats principal {principal} there, and an account's doc 1 is written by its own session alone"),
            "leave --principal (and SKEP_PRINCIPAL) out, or name the account that principal holds",
        )
        .into());
    }
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Sign)?;
    let signer = store.signer(&KeySelector::Path(&key.path))?;
    // The home's read, ahead of the session (REG-1.52): a draft home halts
    // here, naming its act, with no session opened.
    let reads = FirstSessionReads::take(&board, &account, &key.fingerprint, Some(&store))?;
    // Content scope, as `skep session` opens its: an endpoint is a registry
    // record, never a credential act.
    let session = handshake(&board, Scope::Content, &*signer, principal, Site::Session)?;
    talk(format!("acting as principal {principal} at account {} with key {}", session.account(), key_named(&key)));
    let outcome = run(&board, &session, &*signer, &reads, &origins);
    // The session is closed on every exit; a close the board refuses speaks
    // only where the run itself passed.
    match session.close() {
        Ok(_) => outcome,
        Err(h) => {
            outcome?;
            Err(h.into())
        }
    }
}

/// Mints the home where it is missing, then deposits the endpoint.
///
/// # Errors
///
/// The mint's halts ([`mint_home`]), then the deposit's
/// ([`deposit_endpoint`]); a write stdout refuses is a halt.
fn run(board: &Board, session: &Session<'_>, signer: &dyn Signer, reads: &FirstSessionReads, origins: &[String]) -> Result<(), Stop> {
    if mint_home(board, reads, session, signer)? {
        talk(format!("the home {} is minted, born published — this account's first signed session mints it ahead of its first deposit (REG-1.51, REG-1.52)", reads.home));
    }
    let id = format!("deposit.{}", reads.account);
    let done = deposit_endpoint(board, session.token(), &EndpointDeposit { home: &reads.home, origins, hand: signer, id: &id })?;
    let standing = match &done.replaces {
        Some(replaced) => format!("it names {replaced} as the deposit it replaces, which stays in the home, read as replaced"),
        None => "it is this account's first, and names none".to_string(),
    };
    talk(format!(
        "the endpoint of {} is deposited at position {}, signed by this key: {} — {standing} (REG-1.10); a reader holds it current once it has read the board to that position",
        reads.account,
        done.at,
        origins.join(", then ")
    ));
    data(format!("endpoint {}", done.link))?;
    if let Some(replaced) = &done.replaces {
        data(format!("replaces {replaced}"))?;
    }
    Ok(())
}
