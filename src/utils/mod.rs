use num_bigint::BigUint;

// Public parameter: Depends SIKE Implem
const e2: u64 = 10; // TBD
const e3: u64 = 10; // TBD
const xp2: u64 = 10; // TBD
const xq2: u64 = 10; // TBD
const xr2: u64 = 10; // TBD
const xp3: u64 = 10; // TBD
const xq3: u64 = 10; // TBD
const xr3: u64 = 10; // TBD

// x-coordinate of the point defined by (X: Z) in projective coordinates
#[derive(Clone)]
struct Point {
    x: BigUint,
    z: BigUint,
}

// Montgomery M_{A,1} Curve defined by (A : C) in projective cooridnates
struct Curve {
    a: BigUint,
    c: BigUint,
}

// Point Doubling 
// Alg 3 (p54)
fn double(p: &Point, c: &Curve) -> Point {
    let t0 = &p.x - &p.z;
    let t1 = &p.x + &p.z;
    let t0 = &t0 * &t0;
    let t1 = &t1 * &t1;

    let z = &c.c * &t0;
    let x = &z * &t1;

    let t1 = t1 - &t0;
    let t0 = &c.a * &t1;

    let z = z + t0;
    let z = z * t1;

    Point { x, z }
}

// Repeated point doubling
// Alg 4 (p55)
fn ndouble(p: Point, c: &Curve, n: u64) -> Point {
    let point = p;
    for i in 0..n {
        let point = double(&point, c);
    }
    point
}

// Combined coordinate doubling and addition
// Alg 5 (p55)
fn double_and_add(p: &Point, q: &Point, pq: &Point, c: &Curve) -> (Point, Point) {
    let t0 = &p.x - &p.z;
    let t1 = &p.x + &p.z;

    let x2 = &t0 * &t0;
    let t2 = &q.x - &q.z;

    let x = &q.x - &q.z;

    let t0 = t0 * &t2;

    let z2 = &t1 * &t1;

    let t1 = t1 * &x;
    let t2 = &x2 - &z2;

    let x2 = x2 * &z2;
    let x = &c.a * &t2;
    let z = &t0 - &t1;
    let z2 = &x + z2;
    let x = &t0 + &t1;
    let z2 = z2 * &t2;

    let z = &z * &z;
    let x = &x * &x;
    let z = &pq.x * z;
    let x = &pq.z * x;

    (Point { x: x2, z: z2 }, Point { x, z })
}

// Point tripling
// Alg 6 (p55)
fn triple(p: &Point, c: &Curve) -> Point {
    let t0 = &p.x - &p.z;
    let t2 = &t0 * &t0;
    let t1 = &p.x + &p.z;
    let t3 = &t0 * &t0;
    let t4 = &t0 + &t1;
    let t0 = &t1 - &t0;
    let t1 = &t4 * &t4;
    let t1 = t1 - &t3;
    let t1 = t1 - &t2;
    let t5 = &t3 * &c.a;
    let t3 = t3 * &t5;
    let t6 = &t2 * &c.c;
    let t2 = t2 * &t6;
    let t3 = &t2 - t3;
    let t2 = &t5 - &t6;
    let t1 = t1 * &t2;
    let t2 = &t3 + &t1;
    let t2 = &t2 * &t2;

    let x = &t2 * &t4;

    let t1 = &t3 - t1;
    let t1 = &t1 * &t1;

    let z = &t1 * &t0;

    Point { x, z }
}

// Repeated point tripling
// Alg 7 (p56)
fn ntriple(p: Point, c: &Curve, n: u64) -> Point {
    let point = p;
    for i in 0..n {
        let point = triple(&point, c);
    }
    point
}

// Three point ladder
// Alg 8 (p56)
fn three_pts_ladder(m: Vec<bool>, points: (BigUint, BigUint, BigUint), c: &Curve) -> Point {
    let (p0, p1, p2) = (
        Point {
            x: points.0,
            z: BigUint::from(1 as u8),
        },
        Point {
            x: points.1,
            z: BigUint::from(1 as u8),
        },
        Point {
            x: points.2,
            z: BigUint::from(1 as u8),
        },
    );
    let curve_tmp = Curve {
        a: &c.a + (2 as u8) / (4 as u8),
        c: BigUint::from(1 as u8),
    };

    for b in m {
        if b {
            let (p0, p1) = double_and_add(&p0, &p1, &p2, &curve_tmp);
        } else {
            let (p0, p2) = double_and_add(&p0, &p1, &p2, &curve_tmp);
        }
    }

    p1
}

// Montgomery j-invariant
// Algo 9 (p56)
fn j_invariant(c: &Curve) -> BigUint {
    let j = &c.a * &c.a;

    let t1 = &c.c * &c.c;
    let t0 = &t1 + &t1;
    let t0 = &j - t0;
    let t0 = t0 - &t1;

    let j = &t0 - &t1;

    let t1 = &t1 * &t1;

    let j = j * &t1;

    let t0 = &t0 + &t0;
    let t0 = &t0 + &t0;
    let t1 = &t1 * &t1;
    let t0 = t0 * &t1;
    let t0 = &t0 + &t0;
    let t0 = &t0 + &t0;

    let j = &t0 / j;

    j
}

// Recovering Montgomery curve coefficient
// Algo 10 (p57)
// NOTE: Here we return the curve directly instead of juste the coefficient
fn get_curve_coefficient(points: (BigUint, BigUint, BigUint)) -> Curve {
    let (x_p, x_q, x_pq) = points;

    let t1 = &x_p + &x_q;
    let t0 = &x_p * &x_q;

    let a = &x_pq * &t1;
    let a = a + &t0;

    let t0 = t0 * &x_pq;
    let a = a - (1 as u8);

    let t0 = &t0 + &t0;
    let t1 = t1 + &x_pq;
    let t0 = &t0 + &t0;

    let a = &a * &a;
    let a = a / &t0;
    let a = a - (1 as u8);

    Curve {
        a,
        c: BigUint::from(1 as u8),
    }
}

// Computing the two-isogenious curve
// Algo 11 (p57)
fn two_isogenious_curve(p: &Point) -> Curve {
    let a = &p.x * &p.x;
    let c = &p.z * &p.z;

    Curve { a, c }
}

// Evaluate the two-isogeny at a point
// Algo 12 (p57)
fn two_isogeny_eval(p: &Point, q: &Point) -> Point {
    let t0 = &p.x + &p.z;
    let t1 = &p.x - &p.z;
    let t2 = &q.x + &q.z;
    let t3 = &q.x - &q.z;

    let t0 = t0 * &t3;
    let t1 = t1 * &t2;
    let t2 = &t0 + &t1;
    let t3 = &t0 - &t1;

    let x = &p.x * t2;
    let z = &p.z * t3;

    Point { x, z }
}

// Computing the four-isogenious curve
// Algo 13 (p57)
fn four_isogenious_curve(p: &Point) -> (Curve, BigUint, BigUint, BigUint) {
    let k2 = &p.x - &p.z;
    let k3 = &p.x + &p.z;
    let k1 = &p.z * &p.z;
    let k1 = &k1 + &k1;

    let c = &k1 * &k1;

    let k1 = &k1 + &k1;

    let a = &p.x * &p.x;
    let a = &a + &a;
    let a = &a * &a;

    (Curve { a, c }, k1, k2, k3)
}

// Evaluate the four-isogeny at a point
// Algo 14 (p58)
fn four_isogeny_eval(p: &Point, k1: &BigUint, k2: &BigUint, k3: &BigUint) -> Point {
    let t0 = &p.x + &p.z;
    let t1 = &p.x - &p.z;

    let x = &t0 * k2;
    let z = &t1 * k3;

    let t0 = &t0 * &t1;
    let t0 = &t0 * k1;
    let t1 = &x + &z;

    let z = &x - &z;

    let t1 = &t1 * &t1;

    let z = &z * &z;
    let x = &t0 + &t1;

    let t0 = &z - t0;

    let x = x * &t1;
    let z = z * &t0;

    Point { x, z }
}

// Computing the three-isogenious curve
// Algo 15 (p58)
fn three_isogenious_curve(p: &Point) -> (Curve, BigUint, BigUint) {
    let k1 = &p.x - &p.z;

    let t0 = &k1 * &k1;

    let k2 = &p.x + &p.z;

    let t1 = &k2 * &k2;
    let t2 = &t0 + &t1;
    let t3 = &k1 + &k2;
    let t3 = &t3 * &t3;
    let t3 = &t3 - &t2;
    let t2 = &t1 + &t3;
    let t3 = &t3 + &t0;
    let t4 = &t3 + &t0;
    let t4 = &t4 + &t4;
    let t4 = &t1 + &t4;

    let c = &t2 * &t4;

    let t4 = &t1 + &t2;
    let t4 = &t4 + &t4;
    let t4 = &t4 + &t0;
    let t4 = &t4 * &t3;

    let t0 = &t4 - &c;
    let a = &c + &t0;

    (Curve { a, c }, k1, k2)
}

// Evaluate the three-isogeny at a point
// Algo 16 (p58)
fn three_isogeny_eval(p: &Point, k1: &BigUint, k2: &BigUint) -> Point {
    let t0 = &p.x + &p.z;
    let t1 = &p.x - &p.z;
    let t0 = k1 * t0;
    let t1 = k2 * t1;
    let t2 = &t0 + &t1;
    let t0 = &t1 - &t0;
    let t2 = &t2 * &t2;
    let t0 = &t0 * &t0;

    let x = &p.x * &t2;
    let z = &p.z * &t0;

    Point { x, z }
}

// Computing and evaluating the 2^e isogeny, simple version
// Algo 17 (p59)
fn two_e_iso(
    p: Point,
    c: Curve,
    mut opt: Option<(Point, Point, Point)>,
) -> (Curve, Option<(Point, Point, Point)>) {
    for e in (0..e2 - 2).rev().step_by(2) {
        let p_tmp = ndouble(p.clone(), &c, e);
        let (c, k1, k2, k3) = four_isogenious_curve(&p_tmp);
        let p = four_isogeny_eval(&p, &k1, &k2, &k3);
        opt = match opt {
            Some((p1, p2, p3)) => Some((
                four_isogeny_eval(&p1, &k1, &k2, &k3),
                four_isogeny_eval(&p2, &k1, &k2, &k3),
                four_isogeny_eval(&p3, &k1, &k2, &k3),
            )),
            None => None,
        };
    }
    (c, opt)
}

// Computing and evaluating the 3^e isogeny, simple version
// Algo 19 (p59)
fn three_e_iso(
    p: Point,
    c: Curve,
    mut opt: Option<(Point, Point, Point)>,
) -> (Curve, Option<(Point, Point, Point)>) {
    for e in (0..=e3 - 1).rev() {
        let p_tmp = ntriple(p.clone(), &c, e);
        let (c, k1, k2) = three_isogenious_curve(&p_tmp);
        let p = three_isogeny_eval(&p, &k1, &k2);
        opt = match opt {
            Some((p1, p2, p3)) => Some((
                three_isogeny_eval(&p1, &k1, &k2),
                three_isogeny_eval(&p2, &k1, &k2),
                three_isogeny_eval(&p3, &k1, &k2),
            )),
            None => None,
        };
    }

    (c, opt)
}

// Computing public key on the 2-torsion
// Algo 21 (p62)
// MOTE: p belongs to the input but is not used ... Missing something ?
pub fn isogen2(sk: Vec<bool>) -> (BigUint, BigUint, BigUint) {
    let (c1, c2) = (
        Curve {
            a: BigUint::from(6 as u8),
            c: BigUint::from(1 as u8),
        },
        Curve {
            a: BigUint::from(8 as u8),
            c: BigUint::from(4 as u8),
        },
    );
    let (p1, p2, p3) = (
        Point {
            x: BigUint::from(xp3),
            z: BigUint::from(1 as u8),
        },
        Point {
            x: BigUint::from(xq3),
            z: BigUint::from(1 as u8),
        },
        Point {
            x: BigUint::from(xr3),
            z: BigUint::from(1 as u8),
        },
    );
    let p = three_pts_ladder(
        sk,
        (BigUint::from(xp2), BigUint::from(xq2), BigUint::from(xr2)),
        &c1,
    );

    let opt = Some((p1, p2, p3));
    let (_, opt) = two_e_iso(p, c2, opt);

    let (p1, p2, p3) = opt.unwrap();

    (p1.x / p1.z, p2.x / p2.z, p3.x / p3.z)
}

// Computing public key on the 3-torsion
// Algo 22 (p62)
// MOTE: p belongs to the input but is not used ... Missing something ?
pub fn isogen3(sk: Vec<bool>) -> (BigUint, BigUint, BigUint) {
    let (c1, c2) = (
        Curve {
            a: BigUint::from(6 as u8),
            c: BigUint::from(1 as u8),
        },
        Curve {
            a: BigUint::from(8 as u8),
            c: BigUint::from(4 as u8),
        },
    );
    let (p1, p2, p3) = (
        Point {
            x: BigUint::from(xp2),
            z: BigUint::from(1 as u8),
        },
        Point {
            x: BigUint::from(xq2),
            z: BigUint::from(1 as u8),
        },
        Point {
            x: BigUint::from(xr2),
            z: BigUint::from(1 as u8),
        },
    );
    let p = three_pts_ladder(
        sk,
        (BigUint::from(xp3), BigUint::from(xq3), BigUint::from(xr3)),
        &c1,
    );

    let opt = Some((p1, p2, p3));
    let (_, opt) = three_e_iso(p, c2, opt);

    let (p1, p2, p3) = opt.unwrap();

    (p1.x / p1.z, p2.x / p2.z, p3.x / p3.z)
}

// Establishing shared keys on the 3-torsion
// Algo 23 (p63)
pub fn isoex2(sk: Vec<bool>, pk: (BigUint, BigUint, BigUint)) -> BigUint {
    let c = get_curve_coefficient(pk.clone());
    let p = three_pts_ladder(sk, pk, &c);

    let c_tmp = Curve {
        a: c.a + BigUint::from(2 as u8),
        c: BigUint::from(4 as u8),
    };
    let (c_tmp, _) = two_e_iso(p, c_tmp, None);

    let c = Curve {
        a: BigUint::from(4 as u8) * c_tmp.a - BigUint::from(2 as u8) * &c_tmp.c,
        c: c_tmp.c,
    };

    j_invariant(&c)
}

// Establishing shared keys on the 2-torsion
// Algo 24 (p63)
pub fn isoex3(sk: Vec<bool>, pk: (BigUint, BigUint, BigUint)) -> BigUint {
    let c = get_curve_coefficient(pk.clone());
    let p = three_pts_ladder(sk, pk, &c);

    let c_tmp = Curve {
        a: &c.a + BigUint::from(2 as u8),
        c: &c.a - BigUint::from(2 as u8),
    };
    let (c_tmp, _) = three_e_iso(p, c_tmp, None);

    let c = Curve {
        a: BigUint::from(2 as u8) * (&c_tmp.a + &c_tmp.c),
        c: &c_tmp.a - &c_tmp.c,
    };

    j_invariant(&c)
}
