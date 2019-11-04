/// Computing optimised strategy, compute_strategy, Alg 46 p75
/// Input: strategy size n, parameters p, q
/// Output: optimal strategy of size n  

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
