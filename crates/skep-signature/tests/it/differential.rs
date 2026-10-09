//! THE TAG-1 DIFFERENTIAL: the pinned `ml-dsa` held byte for byte to
//! `fips204`, a second pure-Rust FIPS 204 implementation, over the fixed
//! frames (`frames.rs`).

use skep_identity::ALG_MLDSA65_ED25519;
use skep_signature::{derive_half_seeds, HybridSigner};

use crate::frames::fixed_frames;

/// THE DIFFERENTIAL TEST for tag 1 (the PQ investigation §8.4 (4), §8.5
/// (ii)): `ml-dsa` 0.1.1's keys from ξ and its deterministic signatures are
/// byte-equal to `fips204` 0.4.6's, a second pure-Rust FIPS 204, over
/// sixteen seeds and the thirteen fixed frames — the gate every future bump
/// of the pinned crate must pass, since FIPS 204 fixes `KeyGen_internal(ξ)`
/// and the deterministic variant.
#[test]
fn tag_1_is_byte_equal_to_a_second_fips_204_implementation() {
    use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
    for i in 0..16u8 {
        let seed = [i; 32];
        let halves = derive_half_seeds(1, &seed).unwrap();
        // `ml-dsa`'s side: the PQ half of the hybrid key and its signature.
        let ours = HybridSigner::from_seed(1, &seed).unwrap();
        let our_pk = ours.public_key().pq_half().to_vec();
        // `fips204`'s side, from the same ξ.
        let (their_pk, their_sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&halves.pq);
        assert_eq!(our_pk, their_pk.clone().into_bytes().to_vec(), "seed {i}: the public key");
        for (name, frame) in fixed_frames(ALG_MLDSA65_ED25519) {
            let our_sig = ours.sign(&frame);
            let our_pq = &our_sig[..ours.public_key().sig_alg_row().pq_sig_len];
            let their_sig = their_sk.try_sign_with_seed(&[0u8; 32], &frame, &[]).unwrap();
            assert_eq!(our_pq, &their_sig[..], "seed {i}, `{name}`: the deterministic signature");
            assert!(their_pk.verify(&frame, &their_sig, &[]), "their verify of their own");
            let as_theirs: [u8; fips204::ml_dsa_65::SIG_LEN] = our_pq.try_into().unwrap();
            assert!(their_pk.verify(&frame, &as_theirs, &[]), "their verify of ours");
        }
    }
}
