use halo2_gadgets::poseidon::primitives::{Spec, generate_constants, Mds};
use halo2_proofs::{arithmetic::Field, plonk::{Column, Selector, Advice, Error, ConstraintSystem, Instance, Expression}, circuit::{Chip, Layouter, AssignedCell, Value}, pasta::Fp, poly::Rotation};

use super::poseidon_chip_2_inputs::{PoseidonConfig, PoseidonChip};

/// Merkle chip hashes 2 values until getting to the root, which gets compared to public input. 
/// Examples that were used:
/// https://github.com/summa-dev/halo2-experiments/blob/main/src/chips/merkle_v3.rs
/// https://github.com/summa-dev/halo2-experiments/blob/main/src/circuits/poseidon.rs

#[derive(Clone, Debug)]
pub struct MerkleConfig<const WIDTH: usize, const RATE: usize> {
  pub input0: Column<Advice>, // inputs to hash
  pub input1: Column<Advice>, // 
  pub swap: Column<Advice>, // whether the inputs must be swapped
  pub output: Column<Instance>, // output
  pub bool_selector: Selector, // to check whether `swap` is binary
  pub swap_selector: Selector, // to check whether input0 and input1 should be swapped before hashing
  pub poseidon_config: PoseidonConfig<WIDTH, RATE>
}

pub struct MerkleChip<const WIDTH: usize, const RATE: usize> {
  config: MerkleConfig<WIDTH, RATE>
}

impl<const WIDTH: usize, const RATE: usize> Chip<Fp> for MerkleChip<WIDTH, RATE> {
    type Config = MerkleConfig<WIDTH, RATE>;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Debug, Clone, Copy)]
struct MySpec<const WIDTH: usize, const RATE: usize>;

impl<const WIDTH: usize, const RATE: usize> Spec<Fp, WIDTH, RATE> for MySpec<WIDTH, RATE> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        0
    }

    fn constants() -> (Vec<[Fp; WIDTH]>, Mds<Fp, WIDTH>, Mds<Fp, WIDTH>) {
        generate_constants::<_, Self, WIDTH, RATE>()
    }
}

/// If `a` then `b`, else `c`. Returns (a * b) + (1 - a) * c.
///
/// `a` must be a boolean-constrained expression.
pub fn ternary<F: Field>(boolean: Expression<F>, op1: Expression<F>, op2: Expression<F>) -> Expression<F> {
  let one = Expression::Constant(F::ONE);
  let one_minus_bool = one-boolean.clone();
  boolean.clone() * op1 + one_minus_bool * op2
}

impl<const WIDTH: usize, const RATE: usize> MerkleChip<WIDTH, RATE> {
  pub fn construct(config: MerkleConfig<WIDTH, RATE>) -> Self {
    Self {
      config,
    }
  }

  pub fn configure(
    meta: &mut ConstraintSystem<Fp>,
    leaf: Column<Advice>,
    proof_elm: Column<Advice>,
    swap: Column<Advice>,
    hash: Column<Instance>
  ) -> MerkleConfig<WIDTH, RATE> {
    // The chip must adhere to 2 main "functionalities": an optional swap and a hash
    meta.enable_equality(leaf);
    meta.enable_equality(proof_elm);
    meta.enable_equality(swap);
    meta.enable_equality(hash);
    
    // Step 1: check a swap has been performed if needed
    // (This could be a separate chip but is incorporated here.)
    // Two gates:
    // - `swap` is binary
    // - constraint on the cells that makes sure swap happens if needed

    // `swap` is an arbitrary Fp value, but we constrain it to be binary.
    // bool_check_selector * swap * (1-swap) = 0 <=> swap == 0 OR swap == 1
    let bool_check_selector = meta.selector();

    meta.create_gate("swap binary", |virtual_cells| {
      let s = virtual_cells.query_selector(bool_check_selector);
      let swap_value = virtual_cells.query_advice(swap, Rotation::cur());
      vec![s * swap_value.clone() * (Expression::Constant(Fp::ONE) - swap_value)]
    });

    // Checking the actual swap
    // We look at 2 rows, first row is input, second row should contain swapped values
    let swap_selector = meta.selector();
    meta.create_gate("swapped", |virtual_cells| {
      let s = virtual_cells.query_selector(swap_selector);
      let a0 = virtual_cells.query_advice(leaf, Rotation::cur());
      let b0 = virtual_cells.query_advice(proof_elm, Rotation::cur());
      let swap_value = virtual_cells.query_advice(swap, Rotation::cur());
      let a1 = virtual_cells.query_advice(leaf, Rotation::next());
      let b1 = virtual_cells.query_advice(proof_elm, Rotation::next());

      // These should both be 0
      let a_correct = a1 - ternary::<Fp>(swap_value.clone(), b0.clone(), a0.clone());
      let b_correct = b1 - ternary::<Fp>(swap_value.clone(), a0.clone(), b0.clone());
      // add and multiply to make sure they are both 0
      vec![s * (a_correct.clone() + b_correct.clone() + (a_correct.clone() * b_correct.clone()))]
    });

    // Step 2: the 2 inputs should give hash output as expected
    let hash_inputs = (0..WIDTH).map(|_| {
      meta.advice_column()
    }).collect();

    let poseidon_config =
            PoseidonChip::<Fp, MySpec<WIDTH, RATE>, WIDTH, RATE>::configure(meta, hash_inputs);

    MerkleConfig { 
      input0: leaf, 
      input1: proof_elm, 
      swap: swap, 
      output: hash, 
      bool_selector: bool_check_selector, 
      swap_selector: swap_selector, 
      poseidon_config: poseidon_config }
  }

  pub fn set_leaf(
      &self,
      mut layouter: impl Layouter<Fp>,
      leaf_val: Value<Fp>
    ) -> Result<AssignedCell<Fp,Fp>, Error> {
      layouter.assign_region(|| "set leaf", |mut region| {
        region.assign_advice(|| "val", self.config.input0, 0, || leaf_val)
      })
  }

  pub fn next_level(
      &self,
      mut layouter: impl Layouter<Fp>,
      previous_elm: &AssignedCell<Fp,Fp>,
      next_elm: Value<Fp>,
      swap: Value<u64> // 1 is true, 0 is false
    ) -> Result<AssignedCell<Fp,Fp>, Error> {
      let (left_input, right_input) = layouter.assign_region(|| "next level", |mut region| {
        // Set needed selectors
        self.config.bool_selector.enable(&mut region, 0)?;
        self.config.swap_selector.enable(&mut region, 0)?;
        // Copy from previous cell
        let cell_a = previous_elm.copy_advice(|| "copied prev elm", &mut region, self.config.input0, 0)?;
        // Set new values
        let cell_b = region.assign_advice(|| "set next elm of proof", self.config.input1, 0, || next_elm)?;
        let cell_swap = region.assign_advice(|| "swap boolean", self.config.swap, 0, || swap.map(|x| if x == 1 {Fp::ONE} else {Fp::ZERO}))?;

        let a_swapped = 
        cell_swap.value().zip(cell_a.value().zip(cell_b.value()))
          .map(|(swap_bool, (a_val, b_val))| {if *swap_bool == Fp::ONE {*b_val} else {*a_val}});
        let b_swapped = 
          cell_swap.value().zip(cell_a.value().zip(cell_b.value()))
            .map(|(swap_bool, (a_val, b_val))| {if *swap_bool == Fp::ONE {*a_val} else {*b_val}});
  

        // Setting next row with possibly swapped values
        let cell_a_swapped = region.assign_advice(
          || "input0 swapped",
          self.config.input0,
          1,
          || a_swapped)?;
          
        let cell_b_swapped = region.assign_advice(
          || "input1 swapped",
          self.config.input1,
          1,
          || b_swapped)?;

        Ok((cell_a_swapped, cell_b_swapped))
      })?;

      // instantiate the poseidon_chip
      let poseidon_chip = 
        PoseidonChip::<Fp, MySpec<WIDTH, RATE> , WIDTH, RATE>::construct(self.config.poseidon_config.clone());

      // The hash function inside the poseidon_chip performs the following action
      // 1. Copy the left and right cells from the previous row
      // 2. Perform the hash function and assign the digest to the current row
      // 3. Constrain the digest to be equal to the hash of the left and right values
      let input_cells: [AssignedCell<Fp,Fp>; 2] = [left_input, right_input];
      let digest =
          poseidon_chip.hash(layouter.namespace(|| "hash row constaint"), input_cells)?;
      Ok(digest)
  }

  pub fn expose_public(
      &self, 
      mut layouter: impl Layouter<Fp>, 
      cell: AssignedCell<Fp,Fp>,
      row: usize
    ) -> Result<(), Error> {
      layouter.constrain_instance(cell.cell(), self.config.output, row)
  }
}