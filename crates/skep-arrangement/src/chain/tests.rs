use super::*;
use crate::testutil::{a, doc1, pca, pdoc, seeded_m3};
use skep_namespace::M3Rec;

/// PUB-2.49/2.50/2.53/2.66 — the float, over every case it decides: a
/// private document answers itself whether or not a member exists under
/// it; a published document answers itself while memberless, its trunk
/// head once one exists, and a version address answers itself forever —
/// a daughter never floating anything.
#[test]
fn a_bare_published_address_floats_to_its_trunk_head_and_nothing_else_moves() {
    let m3 = seeded_m3();
    // Memberless: a published document answers its own arrangement.
    assert_eq!(trunk_head(&m3, &pdoc()), None);
    assert_eq!(reading_surface(&m3, &pdoc()), pdoc());
    // The chain grows two trunk members and a daughter of the first.
    let member1 = a(&[1, 0, 1, 0, 3, 1]);
    let member2 = a(&[1, 0, 1, 0, 3, 2]);
    let daughter = a(&[1, 0, 1, 0, 3, 1, 1]);
    let m3 = m3
        .apply_m3(&M3Rec::allocate(member1.clone(), true))
        .apply_m3(&M3Rec::allocate(member2.clone(), true))
        .apply_m3(&M3Rec::allocate(daughter.clone(), true));
    assert_eq!(trunk_head(&m3, &pdoc()), Some(member2.clone()));
    assert_eq!(reading_surface(&m3, &pdoc()), member2, "the bare address floats to the head");
    // Every version address answers itself, the head included — and
    // asked about the trunk head, a member and a daughter both name the
    // one trunk.
    for member in [&member1, &member2, &daughter] {
        assert_eq!(reading_surface(&m3, member), *member, "a version address answers itself");
        assert_eq!(trunk_head(&m3, member), Some(member2.clone()), "one trunk, whoever asks");
    }
    // Inert on a private document, even one a fixture stamped a member
    // under: the float keys on the publication bit.
    let stamped = m3.apply_m3(&M3Rec::allocate(a(&[1, 0, 1, 0, 1, 1]), true));
    assert_eq!(trunk_head(&stamped, &doc1()), Some(a(&[1, 0, 1, 0, 1, 1])));
    assert_eq!(reading_surface(&stamped, &doc1()), doc1(), "a private document never floats");
}

/// PUB-2.65/2.66 — where a declared deposit lands, over every case it
/// decides: a memberless edition takes its own deposits; once the chain
/// has a head, every address of the chain lands there — the bare
/// document, the head itself, a pinned member and a daughter alike — and a
/// private document takes its own inserts whatever a fixture stamped under
/// it. The daughter is also what makes the pinned member a real case: it
/// gives member1 a daughter chain, whose latest is not the trunk's head.
#[test]
fn a_declared_deposit_lands_on_the_head_whichever_chain_address_it_names() {
    let m3 = seeded_m3();
    let edition = pdoc();
    assert_eq!(deposit_surface(&m3, &edition), edition, "memberless: its own arrangement");
    let member1 = a(&[1, 0, 1, 0, 3, 1]);
    let member2 = a(&[1, 0, 1, 0, 3, 2]);
    let daughter = a(&[1, 0, 1, 0, 3, 1, 1]);
    let m3 = m3
        .apply_m3(&M3Rec::allocate(member1.clone(), true))
        .apply_m3(&M3Rec::allocate(member2.clone(), true))
        .apply_m3(&M3Rec::allocate(daughter.clone(), true));
    assert_eq!(m3.latest_version(&member1), Some(daughter.clone()), "member1's daughter chain");
    for named in [&edition, &member1, &member2, &daughter] {
        assert_eq!(
            deposit_surface(&m3, named),
            member2,
            "{named:?}: a declared deposit lands on the head"
        );
    }
    // The one address the two surfaces answer differently: a pinned
    // member, which its readers answer forever and which never grows.
    assert_eq!(reading_surface(&m3, &member1), member1);
    assert_ne!(deposit_surface(&m3, &member1), reading_surface(&m3, &member1));
    // A private document's declaration is inert: the insert edits the
    // arrangement named, even with a member stamped under it.
    let stamped = m3.apply_m3(&M3Rec::allocate(a(&[1, 0, 1, 0, 1, 1]), true));
    assert_eq!(deposit_surface(&stamped, &doc1()), doc1());
}

/// PUB-2.34/2.15 — the birth version is the member that opens the
/// TRUNK's chain, whichever chain address asks: the trunk, the birth
/// version itself, a later member and a daughter of that member all
/// answer `D.1`, never the first address of the chain THEY anchor — the
/// daughter's is `D.2.1.1`, the later member's `D.2.1`, and M3 would mint
/// either as readily. A memberless chain, an account, an element and an
/// unregistered document have no head and no birth version (TOTAL reads),
/// and the fold's `is_birth_version`, asking the address alone, agrees.
#[test]
fn the_birth_version_is_the_trunks_first_member_whoever_asks() {
    let m3 = seeded_m3();
    let trunk = pdoc();
    assert_eq!(birth_version(&m3, &trunk), None, "memberless");
    let member1 = a(&[1, 0, 1, 0, 3, 1]);
    let member2 = a(&[1, 0, 1, 0, 3, 2]);
    let daughter = a(&[1, 0, 1, 0, 3, 2, 1]);
    let m3 = m3
        .apply_m3(&M3Rec::allocate(member1.clone(), true))
        .apply_m3(&M3Rec::allocate(member2.clone(), true))
        .apply_m3(&M3Rec::allocate(daughter.clone(), true));
    for named in [&trunk, &member1, &member2, &daughter] {
        assert_eq!(birth_version(&m3, named), Some(member1.clone()), "{named:?}");
        assert_eq!(is_birth_version(named), *named == member1, "{named:?}");
    }
    for headless in [a(&[1, 0, 1]), pca(1), a(&[1, 0, 1, 0, 9])] {
        assert_eq!(trunk_head(&m3, &headless), None, "{headless:?}");
        assert_eq!(birth_version(&m3, &headless), None, "{headless:?}");
        assert!(!is_birth_version(&headless), "{headless:?}");
    }
}

/// PUB-2.11/2.15 — the bit that decides every refusal is the DOCUMENT's,
/// read after the projection: a member stamped with the bit its document
/// does not carry answers as its document, whichever way the stamp
/// points. M3's own read answers the stamp, which is why the projection
/// is this read's to make.
#[test]
fn the_publication_read_judges_a_member_as_its_document() {
    let member_of_draft = a(&[1, 0, 1, 0, 1, 1]);
    let member_of_edition = a(&[1, 0, 1, 0, 3, 1]);
    let m3 = seeded_m3()
        .apply_m3(&M3Rec::allocate(member_of_draft.clone(), true))
        .apply_m3(&M3Rec::allocate(member_of_edition.clone(), false));
    assert!(!published_target(&m3, &doc1()));
    assert!(!published_target(&m3, &member_of_draft), "a published-stamped member of a draft");
    assert!(published_target(&m3, &pdoc()));
    assert!(published_target(&m3, &member_of_edition), "a private-stamped member of an edition");
    assert!(m3.published(&member_of_draft), "M3 answers the member's own stamp");
}

/// PUB-2.15's projection is address arithmetic and total: a version
/// member answers its document, a document answers itself, a member of
/// a member answers the same document — and off the document tier the
/// arithmetic changes nothing, an account and an element each answering
/// itself. The element case is why the projection asks the tier before
/// it cuts: only a document's field ends its address. An element MINTED
/// UNDER A MEMBER carries the member's two-component document field and
/// then its own element field, so cutting that document field's version
/// component off the address's end would take the element's ordinal
/// instead — answering a subspace base, neither the element nor a
/// document. `document_of` first is how a caller asks for an element's
/// trunk, and it answers the same document for both.
#[test]
fn a_version_member_projects_to_its_document() {
    let doc = a(&[1, 0, 1, 0, 1]);
    assert_eq!(trunk_of(&doc), doc, "a document is its own trunk");
    assert_eq!(trunk_of(&a(&[1, 0, 1, 0, 1, 1])), doc, "a version");
    assert_eq!(trunk_of(&a(&[1, 0, 1, 0, 1, 1, 2])), doc, "a version of a version");
    let acct = a(&[1, 0, 1]);
    assert_eq!(trunk_of(&acct), acct);
    let element = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
    assert_eq!(trunk_of(&element), element, "an element of the trunk");
    let member_element = a(&[1, 0, 1, 0, 1, 1, 0, 1, 1]);
    assert_eq!(trunk_of(&member_element), member_element, "an element of a member");
    for e in [&element, &member_element] {
        let document = skep_address::document_of(e).expect("an element lies in a document");
        assert_eq!(trunk_of(&document), doc, "{e:?}: its document's trunk");
    }
}

/// PUB-2.15/2.16 — the trunk is the answer M1's `parent` step reaches
/// taken once per version component, at every depth the wire admits: a
/// document field of 1, 2, 3, 64 and 249 components under account
/// `[1,0,1]`, the last making an element of it 256 components long — the
/// wire's deepest address. The oracle peels; the projection cuts once,
/// which is what keeps a request naming a deep member from buying a cost
/// quadratic in the depth it chose, and it must agree with the peel at
/// every depth. An element minted under the deepest member still answers
/// itself.
#[test]
fn the_trunk_is_one_truncation_at_every_depth_the_wire_admits() {
    let peeled = |member: &Address| {
        let mut trunk = member.clone();
        while trunk.document_field().is_some_and(|field| field.len() > 1) {
            trunk = skep_address::parent(&trunk).expect("a member peels to its document");
        }
        trunk
    };
    let doc = a(&[1, 0, 1, 0, 1]);
    let mut deepest = 0;
    for depth in [1usize, 2, 3, 64, 249] {
        let mut comps = vec![1u32, 0, 1, 0];
        comps.resize(4 + depth, 1);
        let member = a(&comps);
        assert_eq!(member.document_field().map(|field| field.len()), Some(depth));
        assert_eq!(trunk_of(&member), doc, "a document field of {depth}");
        assert_eq!(trunk_of(&member), peeled(&member), "the M1 step, once per component, at {depth}");
        comps.extend([0, 1, 1]);
        let element = a(&comps);
        assert_eq!(trunk_of(&element), element, "an element of a member {depth} deep");
        deepest = element.tumbler().len();
    }
    assert_eq!(deepest, 256, "the deepest element is the wire's deepest address");
}
