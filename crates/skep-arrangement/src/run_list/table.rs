//! The node table: the lists of a slice written as one table of nodes (§1).
//!
//! The lists a slice holds share nodes — a version's list with its source's,
//! a named list with the arrangement it was named from, an edited list with
//! the list before the edit — and a list written as its runs is written
//! whole, so what two lists share in memory would be written twice and be
//! apart after every open. Here every list of one slice is a *root* of one
//! table: the table holds each node once, a leaf as its runs and an inner
//! node as the ids of its children, and a list is written as the id of its
//! root. Two lists that share a subtree share it in the bytes, and after a
//! decode share it in memory.
//!
//! **The bytes are canonical.** M2 names a checkpoint by the hash of its
//! body, so two writes of one slice must be one byte string, on any process
//! and after any history. Three rules hold it. *The order is the walk's*:
//! the roots are taken in the order their owner names them
//! ([`Writer::root`]), each node is written after its children and at its
//! first meeting, and its id is its place in that order. *Identity is
//! content*: a node is one with a node already written exactly where their
//! contents are equal — a leaf's runs, an inner node's child ids — compared
//! in full, so a node content-equal to an earlier one at another address in
//! memory, as a change and its reversal leave, is one entry. *Nothing else
//! reaches a byte*: a pointer, a hash value and a map's iteration order
//! each only find a candidate — a pointer met already names its node
//! without a comparison, a node being never changed once built; a hash is a
//! bucket key — and none orders or decides anything. The tree's shape, which
//! the table does write, follows the fold's operations alone (`tree`), so a
//! body written after an open is the body written after a replay.
//!
//! **What a write costs** is the distinct nodes, never the sum of the roots'
//! runs: a node met by pointer is not opened again, so a subtree a thousand
//! roots share is walked once.
//!
//! **The decode door** ([`Decoded`]) reads the table a node at a time,
//! reserving nothing from a count the bytes declare, rebuilds each node
//! once — recomputing its sums, of which the bytes carry none — and shares
//! it wherever the table names it. It refuses what it cannot mend
//! ([`Refused`]) and mends what it can: an unmerged seam, by building the
//! nodes above it again through the tree's builder, each once however many
//! lists and nodes name it, every subtree no such seam lies in kept shared.
//! So reading a table costs its entries, whatever they repeat: a table's
//! lists may hold more runs than the table has entries for — content-equal
//! nodes are one entry — and neither the read nor the mend walks those runs.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::sync::Arc;

use num_traits::Zero;
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use skep_address::Nat;

use super::tree::{Builder, Node, View, MAX, MAX_HEIGHT, MIN};
use super::{i_adjacent, RunList};
use crate::run::Run;

/// A list as the table form writes it: the id of its root in the table.
///
/// `None` is the empty list, which has no node. An id is a node's place in
/// the table, counted from 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Root(Option<u64>);

/// One node as the table writes it.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename = "Node")]
enum Written<'l> {
    /// A leaf: its runs in V-order, each through `Run`'s own form.
    Leaf(&'l [Run]),
    /// An inner node: the ids of its children in V-order, each written
    /// before it.
    Inner(Vec<u64>),
}

/// Returns the bucket key of a node's content: a hash of what it writes.
///
/// A key finds the nodes a new one may be equal to and decides nothing: the
/// contents are compared in full. Fixed keys, so the buckets are the same
/// on every process, though no byte depends on that.
fn content_key(node: &Written<'_>) -> u64 {
    let mut hasher = DefaultHasher::new();
    match node {
        Written::Leaf(runs) => {
            0u8.hash(&mut hasher);
            runs.hash(&mut hasher);
        }
        Written::Inner(children) => {
            1u8.hash(&mut hasher);
            children.hash(&mut hasher);
        }
    }
    hasher.finish()
}

/// The table being written: the nodes of every root taken so far, each
/// once, in the order of the canonical walk.
///
/// Built by taking each list of a slice as a [`root`](Writer::root), in the
/// order the slice's form names them, and then serialized as the table: a
/// sequence of nodes. Its `Serialize` and the [`Root`]s it answered are the
/// whole of what a slice writes for its lists.
pub(crate) struct Writer<'l> {
    /// The nodes in the order written: a node's id is its index.
    nodes: Vec<Written<'l>>,
    /// For each node, the node written before it under the same bucket key.
    earlier: Vec<Option<u64>>,
    /// The last node written under each bucket key.
    buckets: HashMap<u64, u64>,
    /// The id of every node met, by its address in memory.
    met: HashMap<*const Node, u64>,
    /// The bucket key of a node's content, asked once of every node the
    /// walk opens.
    bucket: fn(&Written<'_>) -> u64,
}

impl<'l> Writer<'l> {
    /// Returns a table that has taken no root.
    pub(crate) fn new() -> Writer<'l> {
        Writer::keyed_by(content_key)
    }

    /// Returns [`new`](Writer::new) with `bucket` as its bucket key.
    fn keyed_by(bucket: fn(&Written<'_>) -> u64) -> Writer<'l> {
        Writer { nodes: Vec::new(), earlier: Vec::new(), buckets: HashMap::new(), met: HashMap::new(), bucket }
    }

    /// Takes `list` as the next root and returns the id it is written as.
    ///
    /// Every node under the root not yet in the table joins it, children
    /// before their parent and left before right. A node met before by its
    /// address is not opened again, and one whose content equals a node
    /// already written takes that node's id, so the walk opens each node
    /// in memory once and the table holds each distinct content once.
    pub(crate) fn root(&mut self, list: &'l RunList) -> Root {
        Root(list.root.as_ref().map(|root| self.node(root)))
    }

    /// Returns the id of `node`, writing it and what stands under it where
    /// the table does not hold them.
    fn node(&mut self, node: &'l Arc<Node>) -> u64 {
        let address = Arc::as_ptr(node);
        if let Some(&id) = self.met.get(&address) {
            return id;
        }
        let written = match node.view() {
            View::Runs(runs) => Written::Leaf(runs),
            View::Nodes(children) => Written::Inner(children.iter().map(|child| self.node(child)).collect()),
        };
        let key = (self.bucket)(&written);
        let mut candidate = self.buckets.get(&key).copied();
        while let Some(id) = candidate {
            let at = id as usize;
            if self.nodes[at] == written {
                self.met.insert(address, id);
                return id;
            }
            candidate = self.earlier[at];
        }
        let id = self.nodes.len() as u64;
        self.earlier.push(self.buckets.insert(key, id));
        self.nodes.push(written);
        self.met.insert(address, id);
        id
    }
}

/// Writes the table: its nodes in order, as a sequence.
impl Serialize for Writer<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(&self.nodes)
    }
}

/// A map in the table form: a map's keys, each beside the value the table
/// form writes for it.
///
/// The keys are the map's own, in its order, and the values stand in that
/// order: what a slice writes where a map of lists stood, each list now the
/// [`Root`] the table answered for it.
pub(crate) struct Keyed<'l, K, T, V> {
    keys: &'l im::OrdMap<K, T>,
    values: Vec<V>,
}

impl<'l, K, T, V> Keyed<'l, K, T, V> {
    /// Returns `keys`' keys, each beside `value` of its entry.
    pub(crate) fn of(keys: &'l im::OrdMap<K, T>, value: impl FnMut(&'l T) -> V) -> Keyed<'l, K, T, V>
    where
        K: Ord,
    {
        Keyed { keys, values: keys.values().map(value).collect() }
    }
}

/// Writes the map: its length, then each key and its value, in key order.
impl<K: Ord + Serialize, T, V: Serialize> Serialize for Keyed<'_, K, T, V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.values.len()))?;
        for (key, value) in self.keys.keys().zip(&self.values) {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// Why the decode door refused a table.
///
/// Each is a body no fold wrote and no repair can mend; M2 reads the
/// refusal as a base that will not decode and falls back to an older one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// A node of no entry: no node is empty.
    EmptyNode,
    /// A node of more than [`MAX`] entries.
    OverfullNode,
    /// A child id at or past its node's own.
    ///
    /// A node is written after its children, so every cycle is one of
    /// these.
    ForwardId,
    /// An inner node whose children stand at two heights.
    UnevenChildren,
    /// A node taller than a list a machine word counts ([`MAX_HEIGHT`]).
    TooDeep,
    /// A node holding more runs than a machine word counts.
    TooManyRuns,
    /// A root id at or past the table's length.
    RootPastTheTable,
    /// An inner root of one child: a root holds two or more.
    LoneChild,
    /// A node of fewer than [`MIN`] entries that is not a root alone.
    ShortNode,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refused::EmptyNode => "node table: a node holds no entry",
            Refused::OverfullNode => "node table: a node holds more than sixteen entries",
            Refused::ForwardId => "node table: a child id is at or past its node's own",
            Refused::UnevenChildren => "node table: a node's children stand at two heights",
            Refused::TooDeep => "node table: a node is taller than a list a machine word counts",
            Refused::TooManyRuns => "node table: a node holds more runs than a machine word counts",
            Refused::RootPastTheTable => "node table: a root id is past the table",
            Refused::LoneChild => "node table: a root holds one child",
            Refused::ShortNode => "node table: a node that is not a root holds fewer than eight entries",
        })
    }
}

impl std::error::Error for Refused {}

/// One node as the decode door reads it: [`Written`]'s form, its entries
/// read through the bounded door.
#[derive(Deserialize)]
#[serde(rename = "Node")]
enum Read {
    Leaf(#[serde(deserialize_with = "a_nodes_entries")] Vec<Run>),
    Inner(#[serde(deserialize_with = "a_nodes_entries")] Vec<u64>),
}

/// Decodes one node's entries, one at a time, refusing the seventeenth.
///
/// The room is a node's [`MAX`] and never the count the bytes declare, so a
/// count the body does not carry reserves nothing and reads at most one
/// entry past a node's bound before it is refused.
///
/// # Errors
///
/// Returns `D::Error` where an entry does not decode, including where the
/// input runs out before the count its bytes declare, and
/// [`Refused::OverfullNode`] at an entry past `MAX`.
fn a_nodes_entries<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Entries<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Entries<T> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a node's entries")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut entries = Vec::with_capacity(MAX);
            while let Some(entry) = seq.next_element()? {
                if entries.len() == MAX {
                    return Err(A::Error::custom(Refused::OverfullNode));
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_seq(Entries(PhantomData))
}

/// One decoded node, and what the door learned of it.
struct Entry {
    node: Arc<Node>,
    /// The ids of the node's children where a seam of the node, or of a
    /// node under it, was read unmerged — none for a leaf — and `None`
    /// where every seam under the node holds.
    unmerged: Option<Box<[u64]>>,
    /// Whether another node names this one as a child.
    child: bool,
    /// Whether a list names this node as its root.
    root: bool,
}

/// The table as decoded: every node rebuilt once, in the order written.
///
/// Reading it is the first half of the door: each node is rebuilt as one
/// `Arc`, its sums recounted, its own seams tested once — between two runs
/// of a leaf, and between the last run of a child and the first of the
/// next — which tests every seam of every list that holds the node, each
/// seam of a list lying inside exactly one node. The second half is the
/// roots: each list is taken by its [`Root`] ([`list`](Decoded::list)),
/// and once every root is taken the nodes are held to the balance rule
/// ([`balanced`](Decoded::balanced)), which only then knows which nodes are
/// roots.
pub(crate) struct Decoded {
    nodes: Vec<Entry>,
    /// The trees mended so far, by the place of the node each was read as:
    /// a node holding an unmerged seam is built again once, however many
    /// lists and nodes name it, and every one of them shares the result.
    mended: HashMap<usize, Arc<Node>>,
    /// How many nodes have been built again: the tests' count of the mend's
    /// work.
    #[cfg(test)]
    mends: u64,
}

impl Decoded {
    /// Rebuilds one node as read and adds it to the table.
    ///
    /// # Errors
    ///
    /// In the order the checks run: [`Refused::EmptyNode`]; then, for an
    /// inner node, child by child and at the first child that breaks one,
    /// [`Refused::ForwardId`], [`Refused::TooDeep`],
    /// [`Refused::UnevenChildren`] and [`Refused::TooManyRuns`]. Each is
    /// judged before the node is built, so no table holds a node taller
    /// than the bound, whether its read ends in a refusal or not.
    fn admit(&mut self, read: Read) -> Result<(), Refused> {
        let id = self.nodes.len();
        let (node, unmerged) = match read {
            Read::Leaf(runs) => {
                if runs.is_empty() {
                    return Err(Refused::EmptyNode);
                }
                let unmerged = runs.windows(2).any(|pair| i_adjacent(&pair[0], &pair[1].i_start));
                (Node::leaf(runs), unmerged.then(|| Box::from([])))
            }
            Read::Inner(ids) => {
                if ids.is_empty() {
                    return Err(Refused::EmptyNode);
                }
                let mut children = Vec::with_capacity(ids.len());
                let mut height = None;
                let mut runs = 0usize;
                let mut unmerged = false;
                for &child in &ids {
                    let entry = usize::try_from(child)
                        .ok()
                        .filter(|child| *child < id)
                        .and_then(|child| self.nodes.get_mut(child))
                        .ok_or(Refused::ForwardId)?;
                    if entry.node.height() >= MAX_HEIGHT {
                        return Err(Refused::TooDeep);
                    }
                    if *height.get_or_insert(entry.node.height()) != entry.node.height() {
                        return Err(Refused::UnevenChildren);
                    }
                    runs = runs.checked_add(entry.node.count()).ok_or(Refused::TooManyRuns)?;
                    unmerged |= entry.unmerged.is_some();
                    entry.child = true;
                    children.push(Arc::clone(&entry.node));
                }
                unmerged |= children.windows(2).any(|pair| match (pair[0].last_run(), pair[1].first_run()) {
                    (Some(last), Some(first)) => i_adjacent(last, &first.i_start),
                    _ => false,
                });
                (Node::inner(children), unmerged.then(|| ids.into_boxed_slice()))
            }
        };
        self.nodes.push(Entry { node, unmerged, child: false, root: false });
        Ok(())
    }

    /// Returns the list written as `root`.
    ///
    /// Its tree is the table's own node, shared with every other list and
    /// node that names it, where every seam under it holds, and the node's
    /// mended tree where one does not ([`mended`](Decoded::mended)). Two
    /// roots of one id answer one tree either way.
    ///
    /// # Errors
    ///
    /// [`Refused::RootPastTheTable`] where the table holds no such node, and
    /// [`Refused::LoneChild`] where the node is an inner node of one child.
    pub(crate) fn list(&mut self, root: Root) -> Result<RunList, Refused> {
        let Root(Some(id)) = root else {
            return Ok(RunList::default());
        };
        let at = usize::try_from(id).ok().filter(|at| *at < self.nodes.len()).ok_or(Refused::RootPastTheTable)?;
        let entry = &mut self.nodes[at];
        if entry.node.children().is_some_and(|children| children.len() < 2) {
            return Err(Refused::LoneChild);
        }
        entry.root = true;
        Ok(RunList { root: self.mended(at) })
    }

    /// Returns the tree read as the node at `at`, every seam under it
    /// merged: `None` only for a node that holds no run, which no table
    /// admits.
    ///
    /// The table's own node where every seam under it holds. Else a tree
    /// built again through the tree's builder, ONCE for the node however
    /// many lists and nodes name it: the runs of a leaf holding an unmerged
    /// seam are placed one by one, each merged into the run before it; the
    /// children of an inner node are taken in order, each as its own mended
    /// tree, kept whole and tested where it opens. So the nodes on the
    /// paths to the unmerged seams are made anew and every subtree no such
    /// seam lies in is shared still, with every other list that names it.
    ///
    /// What it costs is the nodes that hold a seam, each once, and for each
    /// its entries — never the runs under them, which a table that names
    /// one child many times may hold in any number.
    fn mended(&mut self, at: usize) -> Option<Arc<Node>> {
        let entry = &self.nodes[at];
        let Some(children) = entry.unmerged.clone() else {
            return Some(Arc::clone(&entry.node));
        };
        if let Some(tree) = self.mended.get(&at) {
            return Some(Arc::clone(tree));
        }
        let node = Arc::clone(&entry.node);
        let mut out = Builder::new();
        match node.view() {
            View::Runs(runs) => {
                for run in runs {
                    out.place(run.clone(), &mut |_| {});
                }
            }
            View::Nodes(_) => {
                for &child in children.iter() {
                    // Held under the node's own id when it was admitted.
                    if let Some(tree) = self.mended(child as usize) {
                        out.keep(&tree, &Nat::zero(), None, &mut |_| {});
                    }
                }
            }
        }
        let tree = out.finish(&mut |_| {})?;
        #[cfg(test)]
        {
            self.mends += 1;
        }
        self.mended.insert(at, Arc::clone(&tree));
        Some(tree)
    }

    /// Holds every node to the balance rule, once every root is taken.
    ///
    /// A node a list names as its root, and no node names as a child, may
    /// hold fewer than [`MIN`] entries; every other node holds `MIN` or
    /// more. No node holds more than [`MAX`]: the entries' own door refused
    /// it.
    ///
    /// # Errors
    ///
    /// [`Refused::ShortNode`] at the first node that breaks the rule.
    pub(crate) fn balanced(&self) -> Result<(), Refused> {
        let short = |entry: &Entry| (entry.child || !entry.root) && entry.node.len() < MIN;
        if self.nodes.iter().any(short) {
            return Err(Refused::ShortNode);
        }
        Ok(())
    }
}

/// Reads the table a node at a time, reserving nothing by its count.
impl<'de> Deserialize<'de> for Decoded {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Decoded, D::Error> {
        struct Nodes;

        impl<'de> Visitor<'de> for Nodes {
            type Value = Decoded;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a node table")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut nodes: A) -> Result<Decoded, A::Error> {
                let mut table = Decoded {
                    nodes: Vec::new(),
                    mended: HashMap::new(),
                    #[cfg(test)]
                    mends: 0,
                };
                while let Some(read) = nodes.next_element()? {
                    table.admit(read).map_err(A::Error::custom)?;
                }
                Ok(table)
            }
        }

        deserializer.deserialize_seq(Nodes)
    }
}

/// Drops the nodes last first.
///
/// A node's children were read before it, so dropped in that order each
/// node goes while the table still holds its children, and no drop
/// recurses down a chain of them — whatever the table held when a refusal
/// ended its read.
impl Drop for Decoded {
    fn drop(&mut self) {
        while self.nodes.pop().is_some() {}
    }
}

#[cfg(test)]
mod tests;
