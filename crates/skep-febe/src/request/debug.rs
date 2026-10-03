//! [`Op`]'s `Debug`, written out so an `Insert`'s values render as their
//! COUNT — `Vec::len`, since this crate calls no M4 function — where a derive
//! would list one byte length per value, and an insert can carry a value per
//! byte. Every other field renders by its own `Debug`, in the shape a derive
//! would print, and no content byte renders anywhere: M4's `Val`, M6's
//! `DeliveryItem` and M2's `Attestation` redact their payloads the same way.
//!
//! Every arm names every field of its variant, with no `..`, so a field added
//! to a variant fails to compile here until it is rendered. The variant names
//! are written by hand, and `request/tests.rs` pins each against
//! [`Op::kind`]'s.

use std::fmt;

use super::Op;

impl fmt::Debug for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::CreateNewDocument { account, published } => f
                .debug_struct("CreateNewDocument")
                .field("account", account)
                .field("published", published)
                .finish(),
            Op::Delegate { new_prefix, new_id } => f
                .debug_struct("Delegate")
                .field("new_prefix", new_prefix)
                .field("new_id", new_id)
                .finish(),
            Op::RegisterNode { addr } => {
                f.debug_struct("RegisterNode").field("addr", addr).finish()
            }
            Op::Fork { published } => f.debug_struct("Fork").field("published", published).finish(),
            Op::NextAccountPrefix { parent } => {
                f.debug_struct("NextAccountPrefix").field("parent", parent).finish()
            }
            Op::PrincipalPrefix { id } => {
                f.debug_struct("PrincipalPrefix").field("id", id).finish()
            }
            Op::EffectiveOwner { addr } => {
                f.debug_struct("EffectiveOwner").field("addr", addr).finish()
            }
            Op::Insert { doc, at, values, deposit } => f
                .debug_struct("Insert")
                .field("doc", doc)
                .field("at", at)
                .field("values", &format_args!("{} values", values.len()))
                .field("deposit", deposit)
                .finish(),
            Op::Delete { doc, p, width } => f
                .debug_struct("Delete")
                .field("doc", doc)
                .field("p", p)
                .field("width", width)
                .finish(),
            Op::Copy { doc, at, specs } => f
                .debug_struct("Copy")
                .field("doc", doc)
                .field("at", at)
                .field("specs", specs)
                .finish(),
            Op::Rearrange { doc, cuts } => {
                f.debug_struct("Rearrange").field("doc", doc).field("cuts", cuts).finish()
            }
            Op::Version { d_src, published } => f
                .debug_struct("Version")
                .field("d_src", d_src)
                .field("published", published)
                .finish(),
            Op::Publish { doc, shot } => {
                f.debug_struct("Publish").field("doc", doc).field("shot", shot).finish()
            }
            Op::MakeLink { home, from, to, ty, replaces } => f
                .debug_struct("MakeLink")
                .field("home", home)
                .field("from", from)
                .field("to", to)
                .field("ty", ty)
                .field("replaces", replaces)
                .finish(),
            Op::Emit { home, ty, from, to } => f
                .debug_struct("Emit")
                .field("home", home)
                .field("ty", ty)
                .field("from", from)
                .field("to", to)
                .finish(),
            Op::Nullify { home, target } => {
                f.debug_struct("Nullify").field("home", home).field("target", target).finish()
            }
            Op::AssertSup { home, old, new } => f
                .debug_struct("AssertSup")
                .field("home", home)
                .field("old", old)
                .field("new", new)
                .finish(),
            Op::EditLink { original, successor, d_s, d_a } => f
                .debug_struct("EditLink")
                .field("original", original)
                .field("successor", successor)
                .field("d_s", d_s)
                .field("d_a", d_a)
                .finish(),
            Op::ReadLink { a } => f.debug_struct("ReadLink").field("a", a).finish(),
            Op::FollowLink { a, slot } => {
                f.debug_struct("FollowLink").field("a", a).field("slot", slot).finish()
            }
            Op::RetrieveV { specs } => f.debug_struct("RetrieveV").field("specs", specs).finish(),
            Op::RetrieveDocVSpan { doc } => {
                f.debug_struct("RetrieveDocVSpan").field("doc", doc).finish()
            }
            Op::RetrieveDocVSpanSet { doc } => {
                f.debug_struct("RetrieveDocVSpanSet").field("doc", doc).finish()
            }
            Op::ShowOrigin { doc, span } => {
                f.debug_struct("ShowOrigin").field("doc", doc).field("span", span).finish()
            }
            Op::ShowDeletions { d_a, d_b } => {
                f.debug_struct("ShowDeletions").field("d_a", d_a).field("d_b", d_b).finish()
            }
            Op::Compare { rho1, rho2 } => {
                f.debug_struct("Compare").field("rho1", rho1).field("rho2", rho2).finish()
            }
            Op::FindDocsContaining { regions } => {
                f.debug_struct("FindDocsContaining").field("regions", regions).finish()
            }
            Op::Image { d, region } => {
                f.debug_struct("Image").field("d", d).field("region", region).finish()
            }
            Op::FindLinksV { d, region } => {
                f.debug_struct("FindLinksV").field("d", d).field("region", region).finish()
            }
            Op::FindLinksFtt { q } => f.debug_struct("FindLinksFtt").field("q", q).finish(),
            Op::CountV { d, region } => {
                f.debug_struct("CountV").field("d", d).field("region", region).finish()
            }
            Op::CountFtt { q } => f.debug_struct("CountFtt").field("q", q).finish(),
            Op::WindowV { d, region, cur, n } => f
                .debug_struct("WindowV")
                .field("d", d)
                .field("region", region)
                .field("cur", cur)
                .field("n", n)
                .finish(),
            Op::WindowFtt { q, cur, n } => f
                .debug_struct("WindowFtt")
                .field("q", q)
                .field("cur", cur)
                .field("n", n)
                .finish(),
            Op::RetrieveEndsets { d, region } => {
                f.debug_struct("RetrieveEndsets").field("d", d).field("region", region).finish()
            }
            Op::Project { a, slot, d } => f
                .debug_struct("Project")
                .field("a", a)
                .field("slot", slot)
                .field("d", d)
                .finish(),
            Op::DiscoverableFrom { a, d } => {
                f.debug_struct("DiscoverableFrom").field("a", a).field("d", d).finish()
            }
            Op::DeleteOrphans { d, p, width } => f
                .debug_struct("DeleteOrphans")
                .field("d", d)
                .field("p", p)
                .field("width", width)
                .finish(),
            Op::InClaims { y, view } => {
                f.debug_struct("InClaims").field("y", y).field("view", view).finish()
            }
            Op::OutClaims { x, view } => {
                f.debug_struct("OutClaims").field("x", x).field("view", view).finish()
            }
            Op::DocMetadata { doc } => f.debug_struct("DocMetadata").field("doc", doc).finish(),
            Op::EditionClaims { target } => {
                f.debug_struct("EditionClaims").field("target", target).finish()
            }
            Op::UniversalGrants => f.write_str("UniversalGrants"),
        }
    }
}
