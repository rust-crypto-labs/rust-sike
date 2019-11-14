//! Utils for tree traversal strategies

/// 2-torsion tree-traversal strategy
pub type Torsion2Strategy = Vec<usize>;

/// 3-torsion tree-traversal strategy
pub type Torsion3Strategy = Vec<usize>;

/// Tree traversal strategy for 3-torsion (SIKEp434)
pub type Torsion3StrategyP434 = [usize; 136];

/// Tree traversal strategy for 2-torsion (SIKEp434)
pub type Torsion2StrategyP434 = [usize; 107];

/// Tree traversal strategy for 3-torsion (SIKEp503)
pub type Torsion3StrategyP503 = [usize; 158];

/// Tree traversal strategy for 2-torsion (SIKEp503)
pub type Torsion2StrategyP503 = [usize; 124];

/// Tree traversal strategy for 3-torsion (SIKEp610)
pub type Torsion3StrategyP610 = [usize; 191];

/// Tree traversal strategy for 2-torsion (SIKEp610)
pub type Torsion2StrategyP610 = [usize; 151];

/// Tree traversal strategy for 3-torsion (SIKEp751)
pub type Torsion3StrategyP751 = [usize; 238];

/// Tree traversal strategy for 2-torsion (SIKEp751)
pub type Torsion2StrategyP751 = [usize; 185];

/// 2-torsion reference strategy for SIKEp434 (ref C.1.1.)
pub const P434_TWO_TORSION_STRATEGY: Torsion2StrategyP434 = [
    48, 28, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2,
    1, 1, 13, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 4, 2, 1, 1, 2, 1, 1, 2, 1, 1, 1, 21, 12,
    7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 9, 5, 3, 2, 1, 1, 1,
    1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1,
];

/// 3-torsion reference strategy for SIKEp434 (ref C.1.2.)
pub const P434_THREE_TORSION_STRATEGY: Torsion3StrategyP434 = [
    66, 33, 17, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 1, 2, 1,
    1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2,
    1, 1, 4, 2, 1, 1, 2, 1, 1, 32, 16, 8, 4, 3, 1, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2,
    1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2,
    1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1,
];

/// 2-torsion reference strategy for SIKEp503 (ref C.2.1.)
pub const P503_TWO_TORSION_STRATEGY: Torsion2StrategyP503 = [
    61, 32, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2,
    1, 1, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2,
    1, 1, 29, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1,
    2, 1, 1, 13, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 5, 4, 2, 1, 1, 2, 1, 1, 2, 1, 1, 1,
];

/// 3-torsion reference strategy for SIKEp503 (ref C.2.2.)
pub const P503_THREE_TORSION_STRATEGY: Torsion3StrategyP503 = [
    71, 38, 21, 13, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 5, 4, 2, 1, 1, 2, 1, 1, 2, 1, 1,
    1, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 17, 9, 5, 3, 2, 1, 1, 1, 1, 2,
    1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 33, 17, 9, 5,
    3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2,
    1, 1, 16, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1,
    2, 1, 1,
];

/// 2-torsion reference strategy for SIKEp610 (ref C.3.1.)
pub const P610_TWO_TORSION_STRATEGY: Torsion2StrategyP610 = [
    67, 37, 21, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 9,
    5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 16, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1,
    1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 33, 16, 8, 5, 2, 1, 1,
    1, 2, 1, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2,
    1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1,
];

/// 3-torsion reference strategy for SIKEp610 (ref C.3.2.)
pub const P610_THREE_TORSION_STRATEGY: Torsion3StrategyP610 = [
    86, 48, 27, 15, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1,
    1, 1, 1, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 21, 12,
    7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 9, 5, 3, 2, 1, 1, 1,
    1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 38, 21, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5,
    3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 17,
    9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1,
    1, 2, 1, 1,
];

/// 2-torsion reference strategy for SIKEp751 (ref C.4.1.)
pub const P751_TWO_TORSION_STRATEGY: Torsion2StrategyP751 = [
    80, 48, 27, 15, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1,
    1, 1, 1, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 21, 12,
    7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 9, 5, 3, 2, 1, 1, 1,
    1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 33, 20, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5,
    3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 8, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8,
    4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1,
];

/// 3-torsion reference strategy for SIKEp751 (ref C.4.2.)
pub const P751_THREE_TORSION_STRATEGY: Torsion3StrategyP751 = [
    112, 63, 32, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1,
    1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1,
    1, 2, 1, 1, 31, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2,
    1, 1, 2, 1, 1, 15, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2,
    1, 1, 1, 1, 49, 31, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4,
    2, 1, 1, 2, 1, 1, 15, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 7, 4, 2, 1, 1, 2, 1, 1, 3,
    2, 1, 1, 1, 1, 21, 12, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1,
    1, 1, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1,
];

/// Computing optimised strategy (ref `compute_strategy`, Algorithm 46 p. 75).
///   * Input: strategy size `n`, parameters `p`, `q`
///   * Output: optimal strategy of size `n`  
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
