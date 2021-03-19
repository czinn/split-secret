use galois_2p8::Field;

/* Computes the Lagrange basis polynomials for xs[0..k] and evaluates them at each eval_xs.
 * For each x in eval_xs, this function returns the value of the k+1 Lagrange polynomials evaluated
 * at that x.
 */
pub fn lagrange_eval(field: &dyn Field, xs: &[u8], eval_xs: &[u8]) -> Vec<Vec<u8>> {
    let mut lagrange_denominator = vec![1u8; xs.len()];
    for (i, x1) in xs.iter().enumerate() {
        for x2 in xs.iter() {
            if x1 == x2 {
                continue;
            }
            lagrange_denominator[i] = field.mult(lagrange_denominator[i], field.sub(*x1, *x2));
        }
    }
    eval_xs.iter().map(|eval_x| {
        let mut numerator = 1u8;
        for x in xs.iter() {
            numerator = field.mult(numerator, field.sub(*eval_x, *x));
        }
        xs.iter().enumerate().map(|(i, x)| if numerator == 0u8 {
            if *x == *eval_x {
                1u8
            } else {
                0u8
            }
        } else {
            field.div(field.div(numerator, field.sub(*x, *eval_x)), lagrange_denominator[i])
        }).collect()
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use galois_2p8::{PrimitivePolynomialField, IrreducablePolynomial};

    #[test]
    fn test_lagrange() {
        let field = PrimitivePolynomialField::new_might_panic(IrreducablePolynomial::Poly84320);
        let result = lagrange_eval(&field, &[1u8, 2u8, 3u8, 4u8, 5u8], &[1u8, 2u8, 33u8, 109u8, 130u8, 141u8, 236u8]);
        assert_eq!(result, [[1u8, 0u8, 0u8, 0u8, 0u8], [0u8, 1u8, 0u8, 0u8, 0u8], [30u8, 199u8, 254u8, 13u8, 43u8], [240u8, 175u8, 216u8, 15u8, 137u8], [146u8, 138u8, 21u8, 26u8, 22u8], [236u8, 245u8, 3u8, 228u8, 255u8], [98u8, 107u8, 130u8, 91u8, 209u8]]);
    }
}
