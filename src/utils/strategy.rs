//! Utils for tree traversal strategies

/// Tree traversal strategy for 3-torsion
pub type Torsion3Strategy = [usize; 136];

/// Tree traversal strategy for 2-torsion
pub type Torsion2Strategy = [usize; 107];

/// 2-torsion reference strategy (ref C.1.1.)
pub const P434_TWO_TORSION_STRATEGY: Torsion2Strategy = [
    48, 28, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2,
    1, 1, 13, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 4, 2, 1, 1, 2, 1, 1, 2, 1, 1, 1, 21, 12,
    7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 9, 5, 3, 2, 1, 1, 1,
    1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1,
];

/// 3-torsion reference strategy (ref C.1.2.)
pub const P434_THREE_TORSION_STRATEGY: Torsion3Strategy = [
    66, 33, 17, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 1, 2, 1,
    1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2,
    1, 1, 4, 2, 1, 1, 2, 1, 1, 32, 16, 8, 4, 3, 1, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2,
    1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2,
    1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1,
];

/// Computing optimised strategy (ref `compute_strategy`, Algorithm 46 p. 75).
///   - Input: strategy size `n`, parameters `p`, `q`
///   - Output: optimal strategy of size `n`  
///
/// # Examples
/// ```rust
/// let strat = compute_strategy(12, 13, 14);
/// println!("{:?}", strat);
/// ```
pub fn compute_strategy(n: usize, p: u64, q: u64) -> Vec<usize> {
    // 1.
    let mut s = vec![vec![]];

    // 2.
    let mut c = vec![0; 2];

    let eval =
        |c: &Vec<u64>, i: u64, b: u64| c[(i - b) as usize] + c[b as usize] + b * p + (i - b) * q;

    // 3.
    for i in 2..=(n as u64 + 1) {
        // 4.
        let mut min_val = eval(&c, i, 1);
        let mut b = 1;
        for b_val in 2..i {
            let c_val = eval(&c, i, b_val);
            if c_val < min_val {
                min_val = c_val;
                b = b_val;
            }
        }

        // 5.
        let mut new_s = vec![b as usize];
        new_s.extend(&s[(i - b - 1) as usize]);
        new_s.extend(&s[b as usize - 1]);
        s.push(new_s);

        // 6.
        c.push(min_val);
    }

    // 7.
    s.last().unwrap().to_vec()
}
