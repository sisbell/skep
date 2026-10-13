//! THE BOUNDED WAIT: its tries numbered from 1 to the bound, a sleep of the
//! interval before each but the first and never after the last, and no
//! more for a caller that stops at a try.

use std::cell::RefCell;

use super::*;

/// A wait of `n` tries, `ms` milliseconds apart.
fn wait(n: u32, ms: u64) -> Wait {
    Wait { tries: NonZeroU32::new(n).expect("one or more tries"), interval: Duration::from_millis(ms) }
}

/// THE TRIES, PACED: three tries numbered 1 to 3, two sleeps of the
/// interval between them and none after the last; one try, no sleep; a
/// caller that stops at try 2 has slept once.
#[test]
fn the_tries_are_paced_between_and_never_after_the_last() {
    let slept = RefCell::new(Vec::new());
    let sleep = |d: Duration| slept.borrow_mut().push(d);
    assert_eq!(wait(3, 5).paced(&sleep).collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(*slept.borrow(), [Duration::from_millis(5); 2], "between the tries, never after the last");
    slept.borrow_mut().clear();
    assert_eq!(wait(1, 5).paced(&sleep).collect::<Vec<_>>(), [1]);
    assert!(slept.borrow().is_empty(), "one try, no sleep");
    assert_eq!(wait(3, 5).paced(&sleep).find(|&at| at == 2), Some(2));
    assert_eq!(*slept.borrow(), [Duration::from_millis(5)], "a caller that stops at try 2 slept once");
}
