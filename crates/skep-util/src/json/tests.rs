use super::*;

/// Marshal determinism in miniature: obj() sorts, so construction order
/// cannot leak into bytes.
#[test]
fn obj_is_order_insensitive() {
    let a = obj(vec![("b", Value::from(2u64)), ("a", Value::from(1u64))]);
    let b = obj(vec![("a", Value::from(1u64)), ("b", Value::from(2u64))]);
    assert_eq!(bytes(&a), bytes(&b));
}

/// The duplicate-key rule [`obj`] states and the daemon's `refuse_with`
/// leans on: the LAST pair given wins, which is what lets `refuse_with`
/// append `error` behind a caller's fields and be sure the field list
/// cannot displace it.
#[test]
fn obj_keeps_the_last_of_duplicate_keys() {
    let v = obj(vec![("k", Value::from(1u64)), ("a", Value::from(9u64)), ("k", Value::from(2u64))]);
    assert_eq!(v["k"], Value::from(2u64), "the last pair given wins");
    assert_eq!(bytes(&v), br#"{"a":9,"k":2}"#.to_vec(), "and the keys still sort");
}

/// The daemon's `to_bytes`, in miniature: a `Value` built through [`obj`]
/// has string keys only, so serializing it cannot fail.
fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("serializing a serde_json::Value with string keys cannot fail")
}
