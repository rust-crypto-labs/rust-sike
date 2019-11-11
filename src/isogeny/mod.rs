//! Tools for isogeny computations

use std::{collections::VecDeque, convert::TryInto, fmt::Debug};

pub mod curve;
pub mod point;
pub mod publickey;
pub mod publicparams;
pub mod secretkey;

use crate::{ff::FiniteField, isogeny::point::Point, utils::strategy};

pub use crate::isogeny::{
    curve::Curve, publickey::PublicKey, publicparams::PublicParameters, secretkey::SecretKey,
};

/// SIKE structure for computing isogenies
pub struct CurveIsogenies<K> {
    params: PublicParameters<K>,
}

impl<K: FiniteField + Clone + Debug> CurveIsogenies<K> {
    /// Initialise the SIKE structure with given parameters
    pub fn init(params: PublicParameters<K>) -> Self {
        Self { params }
    }

    /// Coordinate doubling (ref. `xDBL`, Algorithm 3 p. 54)
    /// Input: P. Output: [2]P
    fn double(p: &Point<K>, curve: &Curve<K>) -> Point<K> {
        let a_24_plus = &curve.a;
        let c_24 = &curve.c;

        let t0 = p.x.sub(&p.z); // 1.
        let t1 = p.x.add(&p.z); // 2.
        let t0 = t0.mul(&t0); // 3.
        let t1 = t1.mul(&t1); // 4.
        let z = c_24.mul(&t0); // 5.
        let x = z.mul(&t1); // 6.
        let t1 = t1.sub(&t0); // 7.
        let t0 = a_24_plus.mul(&t1); // 8.
        let z = z.add(&t0); // 9.
        let z = z.mul(&t1); // 10.

        Point { x, z }
    }

    // Repeated coordinate doubling (ref `xDBLe` Algorithm 4 p.55)
    // Input: P, e. Output : [2^e]P
    fn ndouble(p: Point<K>, e: u64, curve: &Curve<K>) -> Point<K> {
        if e == 0 {
            return p;
        }
        let mut point = p;
        for _ in 1..=e {
            point = Self::double(&point, curve);
        }
        point
    }

    /// Combined coordinate doubling and differential addition (ref `xDBLADD` Algorithm 5 p.55)
    /// Input: P, Q, Q - P, a_24_plus. Output: 2P, P+Q.
    fn double_and_add(
        p: &Point<K>,
        q: &Point<K>,
        qmp: &Point<K>,
        a_24_plus: &K,
    ) -> (Point<K>, Point<K>) {
        let t0 = p.x.add(&p.z); //1.
        let t1 = p.x.sub(&p.z); // 2.
        let x2 = t0.mul(&t0); // 3.
        let t2 = q.x.sub(&q.z); // 4.
        let xpq = q.x.add(&q.z); // 5.
        let t0 = t0.mul(&t2); // 6.
        let z2 = t1.mul(&t1); // 7.

        let t1 = t1.mul(&xpq); // 8.
        let t2 = x2.sub(&z2); // 9.
        let x2 = x2.mul(&z2); // 10.
        let xpq = t2.mul(a_24_plus); // 11.
        let zpq = t0.sub(&t1); // 12.
        let z2 = xpq.add(&z2); // 13.
        let xpq = t0.add(&t1); // 14.

        let z2 = z2.mul(&t2); // 15.
        let zpq = zpq.mul(&zpq); // 16.
        let xpq = xpq.mul(&xpq); // 17.
        let zpq = qmp.x.mul(&zpq); // 18.
        let xpq = qmp.z.mul(&xpq); // 19.

        let two_p = Point { x: x2, z: z2 };
        let p_plus_q = Point { x: xpq, z: zpq };

        (two_p, p_plus_q)
    }

    /// Coordinate tripling (ref `xTPL` Algorithm 6 p.55)
    /// Input: P. Output: [3]P
    fn triple(p: &Point<K>, curve: &Curve<K>) -> Point<K> {
        let a_24_plus = &curve.a;
        let a_24_minus = &curve.c;

        let t0 = p.x.sub(&p.z); // 1.
        let t2 = t0.mul(&t0); // 2.
        let t1 = p.x.add(&p.z); // 3.
        let t3 = t1.mul(&t1); // 4.
        let t4 = t1.add(&t0); // 5.
        let t0 = t1.sub(&t0); // 6.

        let t1 = t4.mul(&t4); // 7.
        let t1 = t1.sub(&t3); // 8.
        let t1 = t1.sub(&t2); // 9.
        let t5 = t3.mul(&a_24_plus); // 10.
        let t3 = t5.mul(&t3); // 11.
        let t6 = t2.mul(&a_24_minus); // 12.

        let t2 = t2.mul(&t6); // 13.
        let t3 = t2.sub(&t3); // 14.
        let t2 = t5.sub(&t6); // 15.
        let t1 = t2.mul(&t1); // 16.
        let t2 = t3.add(&t1); // 17.
        let t2 = t2.mul(&t2); // 18.

        let x = t2.mul(&t4); // 19.
        let t1 = t3.sub(&t1); // 20.
        let t1 = t1.mul(&t1); // 21.
        let z = t1.mul(&t0); // 22.

        Point { x, z }
    }

    /// Repeated point tripling (ref `xTPLe` Algorithm 7 p.56)
    /// Input: P, e. Output: [E^e]P
    fn ntriple(p: Point<K>, e: u64, curve: &Curve<K>) -> Point<K> {
        if e == 0 {
            return p;
        }
        let mut point = p;
        for _ in 1..=e {
            point = Self::triple(&point, curve);
        }
        point
    }

    /// Three point ladder (ref `Ladder3pt` Algorithm 8 p.56)
    /// Input: m (binary), x_p, x_q, x_(Q-P)
    /// Output: P + [m]Q
    fn three_pts_ladder(m: &[bool], x_p: K, x_q: K, x_qmp: K, curve: &Curve<K>) -> Point<K> {
        let mut p0 = Point::from_x(x_q);
        let mut p1 = Point::from_x(x_p);
        let mut p2 = Point::from_x(x_qmp);

        let one = K::one();
        let two = one.add(&one);
        let four = two.add(&two);

        let a_24_plus = &curve.a.add(&two).div(&four);

        // Start with low weight bits
        for &m_i in m.iter().rev() {
            if m_i {
                let (p0v, p1v) = Self::double_and_add(&p0, &p1, &p2, a_24_plus);
                p0 = p0v;
                p1 = p1v;
            } else {
                let (p0v, p2v) = Self::double_and_add(&p0, &p2, &p1, a_24_plus);
                p0 = p0v;
                p2 = p2v;
            }
        }

        p1
    }

    /// Recovering Montgomery curve coefficient (ref `get_A`, Algorithm 10 p. 57)
    /// Input: x_p, x_q, x_(Q-P)
    /// Output: A
    fn from_points(x_p: K, x_q: K, x_qmp: K) -> Curve<K> {
        let t1 = x_p.add(&x_q); //1.
        let t0 = x_p.mul(&x_q); //2.
        let a = x_qmp.mul(&t1); //3.
        let a = a.add(&t0); //4.

        let t0 = t0.mul(&x_qmp); //5.
        let a = a.sub(&K::one()); //6.
        let t0 = t0.add(&t0); //7.
        let t1 = t1.add(&x_qmp); //8.

        let t0 = t0.add(&t0); //9.
        let a = a.mul(&a); // 10.
        let t0 = t0.inv(); //11.
        let a = a.mul(&t0); // 12.

        let a = a.sub(&t1); // 13.

        Curve::from_coeffs(a, K::one())
    }

    /// Computing the two-isogenous curve (ref `2_iso_curve` Algorithm 11 p.57)
    /// Input: P of order 2 on the curve
    /// Output: E/<P>
    fn two_isogenous_curve(&self, p: &Point<K>) -> Curve<K> {
        let a = p.x.mul(&p.x); // 1.
        let c = p.z.mul(&p.z); // 2.
        let a = a.sub(&c); //3.

        Curve::from_coeffs(a, c)
    }

    /// Evaluate the two-isogeny at a point (ref `2_iso_eval` Algorithm 12 p.57)
    /// Input: P of order 2, Q, both on the curve
    /// Output: Q' on a 2-iso curve
    fn two_isogeny_eval(p: &Point<K>, q: &Point<K>) -> Point<K> {
        let t0 = p.x.add(&p.z); // 1.
        let t1 = p.x.sub(&p.z); // 2.
        let t2 = q.x.add(&q.z); // 3.
        let t3 = q.x.sub(&q.z); // 4.
        let t0 = t0.mul(&t3); // 5.
        let t1 = t1.mul(&t2); // 6.
        let t2 = t0.add(&t1); // 7.
        let t3 = t0.sub(&t1); // 8.
        let x = q.x.mul(&t2); // 9.
        let z = q.z.mul(&t3); // 10.

        Point { x, z }
    }

    /// Computing the four-isogenous curve (ref `4_iso_curve` Algorithm 13 p.57)
    /// Input: P of order 4.  
    /// Output: E/<P> and constants k1, k2, k3
    fn four_isogenous_curve(p: &Point<K>) -> (Curve<K>, K, K, K) {
        let k2 = p.x.sub(&p.z); // 1.
        let k3 = p.x.add(&p.z); // 2.
        let k1 = p.z.mul(&p.z); // 3.
        let k1 = k1.add(&k1); // 4.
        let c = k1.mul(&k1); // 5.
        let k1 = k1.add(&k1); // 6.
        let a = p.x.mul(&p.x); // 7.
        let a = a.add(&a); // 8.
        let a = a.mul(&a); // 9.

        (Curve::from_coeffs(a, c), k1, k2, k3)
    }

    /// Evaluate the four-isogeny at a point (ref `4_iso_eval` Algorithm 14 p. 58)
    /// Input: (k1, k2, k3), Q
    /// Output: Q' on a 4-isogenous curve
    pub fn four_isogeny_eval(k1: &K, k2: &K, k3: &K, q: &Point<K>) -> Point<K> {
        let t0 = q.x.add(&q.z); // 1.
        let t1 = q.x.sub(&q.z); // 2.
        let x = t0.mul(&k2); // 3.
        let z = t1.mul(&k3); // 4.

        let t0 = t0.mul(&t1); // 5.
        let t0 = t0.mul(&k1); // 6.
        let t1 = x.add(&z); // 7.
        let z = x.sub(&z); // 8.

        let t1 = t1.mul(&t1); // 9.
        let z = z.mul(&z); //  10.
        let x = t0.add(&t1); // 11.
        let t0 = z.sub(&t0); // 12.

        let x = x.mul(&t1); // 13.
        let z = z.mul(&t0); // 14.

        Point { x, z }
    }

    /// Computing the three-isogenous curve (ref `3_iso_curve` Algorithm 15 p.58)
    /// Input; P of order 3
    /// Output E/<P> and constants k1, k2
    fn three_isogenous_curve(p: &Point<K>) -> (Curve<K>, K, K) {
        let k1 = p.x.sub(&p.z); // 1.
        let t0 = k1.mul(&k1); // 2.
        let k2 = p.x.add(&p.z); // 3.
        let t1 = k2.mul(&k2); // 4.
        let t2 = t0.add(&t1); // 5.
        let t3 = k1.add(&k2); // 6.

        let t3 = t3.mul(&t3); // 7.
        let t3 = t3.sub(&t2); // 8.
        let t2 = t1.add(&t3); // 9.
        let t3 = t3.add(&t0); // 10.
        let t4 = t3.add(&t0); // 11.
        let t4 = t4.add(&t4); // 12.

        let t4 = t1.add(&t4); // 13.
        let c = t2.mul(&t4); // 14.
        let t4 = t1.add(&t2); // 15.
        let t4 = t4.add(&t4); // 16.
        let t4 = t0.add(&t4); // 17.
        let t4 = t3.mul(&t4); // 18.

        let t0 = t4.sub(&c); // 19.
        let a = c.add(&t0); // 20.

        (Curve::from_coeffs(a, c), k1, k2)
    }
    /// Evaluate the three-isogeny at a point (ref `3_iso_eval` Algorithm 16 p.58)
    /// Input: k1, k2, Q
    /// Output: Q' on the 3-isogenous curve
    pub fn three_isogeny_eval(q: &Point<K>, k1: &K, k2: &K) -> Point<K> {
        let t0 = q.x.add(&q.z); // 1.
        let t1 = q.x.sub(&q.z); // 2.
        let t0 = k1.mul(&t0); // 3.
        let t1 = k2.mul(&t1); // 4.
        let t2 = t0.add(&t1); // 5.
        let t0 = t1.sub(&t0); // 6.
        let t2 = t2.mul(&t2); // 7.
        let t0 = t0.mul(&t0); // 8.
        let x = q.x.mul(&t2); // 9.
        let z = q.z.mul(&t0); // 10.

        Point { x, z }
    }

    /// Computing and evaluating the 2^e isogeny, simple version (ref `2_e_iso` Algorithm 17 p.59)
    /// Input: S of order 2^(e_2)
    /// Optional input: three points on the curve
    /// Output: E/<S>
    /// Optional output: three points on the new curve

    fn two_e_iso(
        &self,
        s: Point<K>,
        opt: Option<(Point<K>, Point<K>, Point<K>)>,
        curve: &Curve<K>,
    ) -> (Curve<K>, Option<(Point<K>, Point<K>, Point<K>)>) {
        let mut c = curve.clone();
        let mut s = s;

        let mut opt_output = vec![];
        if opt.is_some() {
            let (p1, p2, p3) = opt.unwrap();
            opt_output.push(p1);
            opt_output.push(p2);
            opt_output.push(p3);
        }
        let nopt = opt_output.len();

        // 1.
        for e in (0..=self.params.e2 - 2).rev().step_by(2) {
            // 2.
            let t = Self::ndouble(s.clone(), e, &c);

            // 3.
            let (new_c, k1, k2, k3) = Self::four_isogenous_curve(&t);
            c = new_c;

            // 4.
            s = Self::four_isogeny_eval(&k1, &k2, &k3, &s);

            // 5.
            for pos in 0..nopt {
                // 6.
                opt_output[pos] = Self::four_isogeny_eval(&k1, &k2, &k3, &opt_output[pos]);
            }
        }

        // 7.
        if nopt > 0 {
            let p3 = opt_output.pop().unwrap();
            let p2 = opt_output.pop().unwrap();
            let p1 = opt_output.pop().unwrap();
            (c, Some((p1, p2, p3)))
        } else {
            (c, None)
        }
    }

    /// Computing & evaluating 2^e-isogeny, optimised version (ref `2_e_iso` Algorithm 19 p. 60)
    /// Input: S of order 2^(e_2), curve, strategy
    /// Optional input: three points on the curve
    /// Output: E/<S>
    /// Optional output: three points on the new curve

    fn two_e_iso_optim(
        &self,
        s: Point<K>,
        opt: Option<(Point<K>, Point<K>, Point<K>)>,
        curve_plus: &Curve<K>,
        strategy: &[usize],
    ) -> (Curve<K>, Option<(Point<K>, Point<K>, Point<K>)>) {
        assert_eq!(self.params.e2 as usize / 2 - 1, strategy.len());

        let mut curve = curve_plus.clone();

        let mut opt_output = vec![];
        if opt.is_some() {
            let (p1, p2, p3) = opt.unwrap();
            opt_output.push(p1);
            opt_output.push(p2);
            opt_output.push(p3);
        }
        let nopt = opt_output.len();

        // 1.
        let mut queue = VecDeque::new();

        // 2.
        queue.push_back((self.params.e2 / 2, s));

        // 3.
        let mut i = 1;

        // 4.
        while !queue.is_empty() {
            let s_i = if i <= strategy.len() {
                strategy[i - 1].try_into().unwrap()
            } else {
                1
            };

            // 5.
            let (h, p) = queue.pop_back().unwrap();

            // 6.
            if h == 1 {
                // 7.
                let (new_curve, k1, k2, k3) = Self::four_isogenous_curve(&p);
                curve = new_curve;

                // 8.
                let mut tmp_queue = VecDeque::new();

                // 9.
                while !queue.is_empty() {
                    // 10.
                    let (h_prime, p_prime) = queue.pop_front().unwrap();

                    // 11.
                    let p_prime = Self::four_isogeny_eval(&k1, &k2, &k3, &p_prime);

                    // 12.
                    tmp_queue.push_back((h_prime - 1, p_prime));
                }

                // 13.
                queue = tmp_queue;

                // 14.
                for pos in 0..nopt {
                    // 15.
                    opt_output[pos] = Self::four_isogeny_eval(&k1, &k2, &k3, &opt_output[pos]);
                }
            } else if h > s_i {
                // 17.
                queue.push_back((h, p.clone()));

                // 18.
                let p_prime = Self::ndouble(p, 2 * s_i, &curve);

                // 19.
                queue.push_back((h - s_i, p_prime));

                // 20.
                i += 1;
            } else {
                // 22.
                panic!("Invalid strategy!")
            }
        }

        // 23.
        if nopt > 0 {
            let p3 = opt_output.pop().unwrap();
            let p2 = opt_output.pop().unwrap();
            let p1 = opt_output.pop().unwrap();
            (curve, Some((p1, p2, p3)))
        } else {
            (curve, None)
        }
    }

    /// Computing and evaluating the 3^e isogeny, simple version (ref `3_e_iso` Algorithm 18 p.59)
    /// Input: S of order 3^(e_3) on the curve
    /// Optional input : three points on the curve
    /// Output: E/<S>
    /// Optional output: three points on the new curve

    fn three_e_iso(
        &self,
        s: Point<K>,
        opt: Option<(Point<K>, Point<K>, Point<K>)>,
        curve: &Curve<K>,
    ) -> (Curve<K>, Option<(Point<K>, Point<K>, Point<K>)>) {
        let mut c = curve.clone();
        let mut s = s;

        let mut opt_output = vec![];
        if opt.is_some() {
            let (p1, p2, p3) = opt.unwrap();
            opt_output.push(p1);
            opt_output.push(p2);
            opt_output.push(p3);
        }
        let nopt = opt_output.len();

        for e in (0..=self.params.e3 - 1).rev() {
            // 2.
            let t = Self::ntriple(s.clone(), e, &c);

            // 3.
            let (new_c, k1, k2) = Self::three_isogenous_curve(&t);
            c = new_c;

            // 4.
            s = Self::three_isogeny_eval(&s, &k1, &k2);

            // 5.
            for pos in 0..nopt {
                // 6.
                opt_output[pos] = Self::three_isogeny_eval(&opt_output[pos], &k1, &k2);
            }
        }

        if nopt > 0 {
            let p3 = opt_output.pop().unwrap();
            let p2 = opt_output.pop().unwrap();
            let p1 = opt_output.pop().unwrap();
            (c, Some((p1, p2, p3)))
        } else {
            (c, None)
        }
    }

    /// Computing & evaluating 3^e-isogeny, optimised version (ref `3_e_iso` Algorithm 20 p. 61)
    /// Input: S of order 2^(e_2), curve, strategy
    /// Optional input: three points on the curve
    /// Output: E/<S>
    /// Optional output: three points on the new curve

    fn three_e_iso_optim(
        &self,
        s: Point<K>,
        opt: Option<(Point<K>, Point<K>, Point<K>)>,
        _curve: &Curve<K>,
        strategy: &[usize],
    ) -> (Curve<K>, Option<(Point<K>, Point<K>, Point<K>)>) {
        let mut new_curve = Curve::starting_curve();
        let mut opt_output = None;

        assert_eq!(self.params.e3 as usize - 1, strategy.len());

        // 1.
        let mut queue = VecDeque::new();

        //2.
        queue.push_back((self.params.e3, s));

        if opt.is_some() {
            let (mut p1, mut p2, mut p3) = opt.unwrap();

            // 3.
            let mut i = 1;

            //4.
            while !queue.is_empty() {
                let s_i = if i <= strategy.len() {
                    strategy[i - 1].try_into().unwrap()
                } else {
                    1
                };

                // 5.
                let (h, p) = queue.pop_back().unwrap();

                // 6.
                if h == 1 {
                    // 7.
                    let (curve_pm, k1, k2) = Self::three_isogenous_curve(&p);
                    new_curve = curve_pm;

                    // 8.
                    let mut tmp_queue = VecDeque::new();

                    // 9.
                    while !queue.is_empty() {
                        let (h, p) = queue.pop_front().unwrap();
                        let p = Self::three_isogeny_eval(&p, &k1, &k2);
                        tmp_queue.push_back((h - 1, p));
                    }
                    queue = tmp_queue;

                    p1 = Self::three_isogeny_eval(&p1, &k1, &k2);
                    p2 = Self::three_isogeny_eval(&p2, &k1, &k2);
                    p3 = Self::three_isogeny_eval(&p3, &k1, &k2);
                } else if h > s_i {
                    queue.push_back((h, p.clone()));
                    let p = Self::ntriple(p, s_i, &new_curve);
                    queue.push_back((h - s_i, p));
                    i += 1;
                } else {
                    panic!("Invalid strategy!")
                }
            }

            opt_output = Some((p1, p2, p3));
        } else {
            // 3.
            let mut i = 1;

            //4.
            while !queue.is_empty() {
                let s_i = if i <= strategy.len() {
                    strategy[i - 1].try_into().unwrap()
                } else {
                    1
                };

                // 5.
                let (h, p) = queue.pop_back().unwrap();

                // 6.
                if h == 1 {
                    // 7.
                    let (curve_pm, k1, k2) = Self::three_isogenous_curve(&p);
                    new_curve = curve_pm;

                    // 8.
                    let mut tmp_queue = VecDeque::new();

                    // 9.
                    while !queue.is_empty() {
                        let (h, p) = queue.pop_front().unwrap();
                        let p = Self::three_isogeny_eval(&p, &k1, &k2);
                        tmp_queue.push_back((h - 1, p));
                    }
                    queue = tmp_queue;
                } else if h > s_i {
                    queue.push_back((h, p.clone()));
                    let p = Self::ntriple(p, s_i, &new_curve);
                    queue.push_back((h - s_i, p));
                    i += 1;
                } else {
                    panic!("Invalid strategy!")
                }
            }
        }

        (new_curve, opt_output)
    }

    /// Computing public key on the 2-torsion (ref `isogen_2` Algo 21 p.62)
    /// Input: secret key, [tree traversal strategy]
    /// Output: public key
    ///
    pub fn isogen2(
        &self,
        sk: &SecretKey,
        strategy: &Option<strategy::Torsion2Strategy>,
    ) -> PublicKey<K> {
        let one = K::one();
        let two = one.add(&one);
        let four = two.add(&two);
        let six = two.add(&four);
        let eight = four.add(&four);

        // 1.
        let curve = Curve::from_coeffs(six, one);
        let curve_plus = Curve::from_coeffs(eight, four);

        // 2.
        let xp3 = self.params.xp3.clone();
        let p1 = Point::from_x(xp3);
        let xq3 = self.params.xq3.clone();
        let p2 = Point::from_x(xq3);
        let xr3 = self.params.xr3.clone();
        let p3 = Point::from_x(xr3);

        // 3.
        let xp2 = self.params.xp2.clone();
        let xq2 = self.params.xq2.clone();
        let xr2 = self.params.xr2.clone();
        let s = Self::three_pts_ladder(&sk.to_bits(), xp2, xq2, xr2, &curve);

        // 4.
        let opt = Some((p1, p2, p3));

        let (_, opt) = match strategy {
            Some(strat) => self.two_e_iso_optim(s, opt, &curve_plus, strat),
            None => self.two_e_iso(s, opt, &curve_plus),
        };

        // 5.
        let (p1, p2, p3) = opt.unwrap();
        let x1 = p1.x.div(&p1.z);
        let x2 = p2.x.div(&p2.z);
        let x3 = p3.x.div(&p3.z);

        // 6.
        PublicKey { x1, x2, x3 }
    }

    /// Computing public key on the 3-torsion (ref `isogen_3` Algorithm 22 p.62)
    /// Input: secret key
    /// Output: public key
    pub fn isogen3(
        &self,
        sk: &SecretKey,
        strategy: &Option<strategy::Torsion3Strategy>,
    ) -> PublicKey<K> {
        let one = K::one();
        let two = one.add(&one);
        let four = two.add(&two);
        let six = two.add(&four);
        let eight = four.add(&four);

        // 1.
        let curve = Curve::from_coeffs(six, one);
        let curve_pm = Curve::from_coeffs(eight, four);

        // 2.
        let xp2 = self.params.xp2.clone();
        let p1 = Point::from_x(xp2);

        let xq2 = self.params.xq2.clone();
        let p2 = Point::from_x(xq2);

        let xr2 = self.params.xr2.clone();
        let p3 = Point::from_x(xr2);

        // 3.
        let xp3 = self.params.xp3.clone();
        let xq3 = self.params.xq3.clone();
        let xr3 = self.params.xr3.clone();

        let s = Self::three_pts_ladder(&sk.to_bits(), xp3, xq3, xr3, &curve);

        // 4.
        let opt = Some((p1, p2, p3));

        let (_, opt) = match strategy {
            Some(strat) => self.three_e_iso_optim(s, opt, &curve_pm, strat),
            None => self.three_e_iso(s, opt, &curve_pm),
        };

        // 5.
        let (p1, p2, p3) = opt.unwrap();
        let x1 = p1.x.div(&p1.z);
        let x2 = p2.x.div(&p2.z);
        let x3 = p3.x.div(&p3.z);

        // 6.
        PublicKey { x1, x2, x3 }
    }

    /// Establishing shared keys on the 2-torsion, (ref `isoex_2` Algorithm 23 p.63)
    /// Input: secret key, public key, [tree traversal strategy]
    /// Output: j-invariant
    pub fn isoex2(
        &self,
        sk: &SecretKey,
        pk: &PublicKey<K>,
        strategy: &Option<strategy::Torsion2Strategy>,
    ) -> K {
        let one = K::one();
        let two = one.add(&one);
        let four = two.add(&two);

        // 1.
        let curve = Curve::from_public_key(pk).expect("Incorrect public key!");

        // 2.
        let (x1, x2, x3) = (&pk.x1, &pk.x2, &pk.x3);
        let s = Self::three_pts_ladder(&sk.to_bits(), x1.clone(), x2.clone(), x3.clone(), &curve);

        // 3.
        let curve_plus = Curve::from_coeffs(curve.a.add(&two), four.clone());

        // 4.
        let (curve_plus, _) = match strategy {
            Some(strat) => self.two_e_iso_optim(s, None, &curve_plus, strat),
            None => self.two_e_iso(s, None, &curve_plus),
        };

        // 5.
        let curve = Curve::from_coeffs(
            curve_plus.a.mul(&four).sub(&curve_plus.c.mul(&two)),
            curve_plus.c,
        );

        // 6, 7.
        curve.j_invariant()
    }

    /// Establishing shared keys on the 3-torsion (ref `isoex_3` Algorithm 24 p.63)
    /// Input: secret key, public key, [tree traversal strategy]
    /// Output: a j-invariant
    pub fn isoex3(
        &self,
        sk: &SecretKey,
        pk: &PublicKey<K>,
        strategy: &Option<strategy::Torsion3Strategy>,
    ) -> K {
        let one = K::one();
        let two = one.add(&one);

        // 1.
        let curve = Curve::from_public_key(pk).expect("Incorrect public key!");

        // 2.
        let (x1, x2, x3) = (&pk.x1, &pk.x2, &pk.x3);
        let s = Self::three_pts_ladder(&sk.to_bits(), x1.clone(), x2.clone(), x3.clone(), &curve);

        // 3.
        let curve_pm = Curve::from_coeffs(curve.a.add(&two), curve.a.sub(&two));

        // 4.
        let (curve_pm, _) = match strategy {
            Some(strat) => self.three_e_iso_optim(s, None, &curve_pm, strat),
            None => self.three_e_iso(s, None, &curve_pm),
        };

        // 5.
        let curve = Curve::from_coeffs(
            two.mul(&curve_pm.a.add(&curve_pm.c)),
            curve_pm.a.sub(&curve_pm.c),
        );

        // 6, 7.
        curve.j_invariant()
    }
}
