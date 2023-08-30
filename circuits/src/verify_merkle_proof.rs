use halo2_proofs::{circuit::{SimpleFloorPlanner, Value}, arithmetic::Field, plonk::{Circuit, ConstraintSystem}, pasta::Fp};
use crate::chips::merkle_chip::{MerkleConfig, MerkleChip};

/// Circuit that check validity of Merkle proof
/// Examples that were used:
/// https://github.com/summa-dev/halo2-experiments/blob/main/src/chips/merkle_v3.rs
/// https://github.com/summa-dev/halo2-experiments/blob/main/src/circuits/poseidon.rs

const TREE_HEIGHT: usize = 4;
const WIDTH: usize = 3;
const RATE: usize = 2;
const L: usize = 2;

#[derive(Default)]
pub struct MerkleProofCircuit {
  pub leaf: Value<Fp>,
  pub proof_elms: Vec<Value<Fp>>,
  pub swap_values: Vec<Value<u64>>
}

impl Circuit<Fp> for MerkleProofCircuit {
  type Config = MerkleConfig<WIDTH, RATE>;
  type FloorPlanner = SimpleFloorPlanner;

  fn without_witnesses(&self) -> Self {
    Self::default()
  }

  fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
    let col0 = meta.advice_column();
    let col1 = meta.advice_column();
    let col2 = meta.advice_column();
    let col_pub = meta.instance_column();

    // The same Merklechip will be used multiple times
    MerkleChip::<WIDTH, RATE>::configure(meta, col0, col1, col2, col_pub)
  }

  fn synthesize(
    &self, 
    config: Self::Config, 
    mut layouter: impl halo2_proofs::circuit::Layouter<Fp>) -> Result<(), halo2_proofs::plonk::Error> {
    let chip = MerkleChip::construct(config);
    
    let leaf = chip.set_leaf(layouter.namespace(|| "set leaf"), self.leaf)?;
    // Public input on row 0
    chip.expose_public(layouter.namespace(|| "pub leaf"), leaf.clone(), 0)?;

    let mut digest = 
      chip.next_level(layouter.namespace(|| "first level"), &leaf, self.proof_elms[0], self.swap_values[0])?;
    
    for i in 1..self.proof_elms.len() {
      digest = chip.next_level(
        layouter.namespace(|| "next level"), 
        &digest, 
        self.proof_elms[i], 
        self.swap_values[i])?;
    }

    // Public input on row 1
    chip.expose_public(layouter.namespace(|| "root"), digest, 1)?; // TODO uncomment
    Ok(())
  }
}

// Draws the layout of the circuit. Super useful for debugging.
#[cfg(not(target_family = "wasm"))]
pub fn draw_circuit<F: Field>(k: u32, circuit: &MerkleProofCircuit) {
    use plotters::prelude::*;
    let base = BitMapBackend::new("layout_verification_merkle_proof.png", (1600,9000)).into_drawing_area();
    base.fill(&WHITE).unwrap();
    let base = base.titled("Merkle Proof Circuit", ("sans-serif", 24)).unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .mark_equality_cells(true)
        .show_equality_constraints(true)
        .render(k, circuit, &base)
        .unwrap();
}


#[cfg(test)]
mod tests {
  use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3};    
  use halo2_proofs::{pasta::Fp, circuit::Value, dev::MockProver};

  use crate::verify_merkle_proof::MerkleProofCircuit;

  use super::draw_circuit;


  const WIDTH: usize = 3;
  const RATE: usize = 2;
  const L: usize = 2;

  fn compute_merkle_root(leaf: &u64, elements: &Vec<u64>, indices: &Vec<u64>) -> Fp {
      let k = elements.len();
      let mut digest = Fp::from(leaf.clone());
      let mut message: [Fp; 2];
      for i in 0..k {
          if indices[i] == 0 {
              message = [digest, Fp::from(elements[i])];
          } else {
              message = [Fp::from(elements[i]), digest];
          }

          digest = poseidon::Hash::<_, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init()
              .hash(message);
      }
      return digest;
  }

  #[test]
  fn test_merkle_tree_3() {
      let leaf = 88u64;
      let elements = [2u64, 3u64, 4u64, 5u64, 6u64];
      let indices = [0u64, 0u64, 0u64, 0u64, 0u64];

      let root = compute_merkle_root(&leaf, &elements.to_vec(), &indices.to_vec());

      let leaf_fp = Value::known(Fp::from(leaf));
      let elements_fp: Vec<Value<Fp>> = elements.map(|x| Value::known(Fp::from(x))).to_vec();
      let indices_fp: Vec<Value<u64>> = indices.map(|x| Value::known(x)).to_vec();

      let circuit = MerkleProofCircuit {
          leaf: leaf_fp,
          proof_elms: elements_fp,
          swap_values: indices_fp,
      };
      draw_circuit::<Fp>(8, &circuit);

      let correct_public_input = vec![Fp::from(leaf), root];
      let valid_prover = MockProver::run(8, &circuit, vec![correct_public_input]).unwrap();
      valid_prover.assert_satisfied();

      let wrong_public_input = vec![Fp::from(leaf), Fp::from(0)];
      let invalid_prover = MockProver::run(8, &circuit, vec![wrong_public_input]).unwrap();
      assert!(invalid_prover.verify().is_err());
  }
}
