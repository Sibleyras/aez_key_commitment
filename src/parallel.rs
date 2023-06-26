use rayon::prelude::*;

/* Try hard to find a successful outcome. */
pub fn par_search<T: Send>(
    trials: u64,
    test_fun: impl Fn() -> Option<T> + Sync + Send,
) -> Option<T> {
    (0..trials).into_par_iter().find_map_any(|_| test_fun())
}

/* Estimate the probability of some function. */
pub fn par_prob(trials: u64, rand_fun: impl Fn() -> bool + Sync + Send) -> f64 {
    let success = (0..trials).into_par_iter().filter(|_| rand_fun()).count();

    prob(trials, success as u64)
}

pub fn prob(trials: u64, success: u64) -> f64 {
    success as f64 / trials as f64
}
