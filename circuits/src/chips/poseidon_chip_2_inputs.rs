use std::marker::PhantomData;

use halo2_proofs::{arithmetic::Field, plonk::{Advice, Column, ConstraintSystem, Fixed, Error}, circuit::{Chip, Layouter, AssignedCell, Value}, pasta::{Fp, self}};
use halo2_gadgets::poseidon::{Pow5Chip, Pow5Config, primitives::{Spec, ConstantLength}, Hash};

/// Poseidon Chip with 2 hash inputs
/// Examples that were used:
/// https://github.com/summa-dev/halo2-experiments/blob/9293898f3136f5b16b621f66c9787e437461dd75/src/chips/poseidon/hash.rs
/// https://github.com/summa-dev/halo2-experiments/blob/main/src/chips/poseidon/hash_with_instance.rs
/// https://github.com/summa-dev/halo2-experiments/blob/main/src/circuits/poseidon.rs

#[derive(Clone, Debug)]
pub struct PoseidonConfig<const WIDTH: usize, const RATE: usize> {
  inputs: Vec<Column<Advice>>,
  pow5_config: Pow5Config<pasta::Fp, WIDTH, RATE> // halo2 gadget which is configured correctly to be used as a PoseidonChip instance
}

#[derive(Clone, Debug)]
pub struct PoseidonChip<
    F: Field,
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize> {
      config: PoseidonConfig<WIDTH, RATE>,
      _marker: PhantomData<(F, S)>
}

impl<F: Field, S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize> Chip<F> for PoseidonChip<F, S, WIDTH, RATE> {
    type Config = PoseidonConfig<WIDTH, RATE>;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field, S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize> PoseidonChip<F, S, WIDTH, RATE> {

  pub fn construct(config: PoseidonConfig<WIDTH, RATE>) -> Self{
    Self {
      config,
      _marker: PhantomData
    }
  }

  pub fn configure(
    meta: &mut ConstraintSystem<Fp>, 
    inputs: Vec<Column<Advice>>) -> PoseidonConfig<WIDTH, RATE> {

    // Inputs we need for the pow5chip:
    // State always consists of *WIDTH* amount of columns
    // all of these cells will have equality enabled
    for input in inputs.clone() {
      meta.enable_equality(input);
    }

    // Round constants
    // unclear why they're called "a" and "b"
    let rc_a: [Column<Fixed>; WIDTH] = (0..WIDTH).map(|_|{meta.fixed_column()}).collect::<Vec<Column<Fixed>>>().try_into().unwrap();
    let rc_b: [Column<Fixed>; WIDTH] = (0..WIDTH).map(|_|{meta.fixed_column()}).collect::<Vec<Column<Fixed>>>().try_into().unwrap();

    let partial_sbox = meta.advice_column();

    meta.enable_constant(rc_b[0]);//Apparently this is needed

    PoseidonConfig {
      inputs: inputs.clone(),
      pow5_config: Pow5Chip::configure::<S>(
          meta,
          inputs.clone().try_into().unwrap(),
          partial_sbox,
          rc_a,
          rc_b,
      )
    }
  }

  pub fn load_private_inputs(
    &self,
    mut layouter: impl Layouter<F>,
    inputs: [Value<F>; 2]
  ) -> Result<[AssignedCell<F, F>; 2], Error> {
    layouter.assign_region(
        || "load private inputs",
        |mut region| -> Result<[AssignedCell<F, F>; 2], Error> {
          let first_cell = region.assign_advice(|| "val", self.config.inputs[0], 0, || inputs[0])?;
          let second_cell = region.assign_advice(|| "val", self.config.inputs[1], 0, || inputs[1])?;
          Ok([first_cell, second_cell])
        },
    )
  }

  pub fn hash(
      &self, 
      mut layouter: impl Layouter<Fp>,
      input_cells: [AssignedCell<Fp,Fp>; 2]
    ) -> Result<AssignedCell<Fp,Fp>, Error> {
      let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());

      let hasher = Hash::<_, _, S, ConstantLength<2>, WIDTH, RATE>::init(
        pow5_chip,
          layouter.namespace(|| "hasher"),
      )?;
      hasher.hash(layouter.namespace(|| "hash"), input_cells)
  }
}


#[cfg(test)]
mod tests {
  use std::marker::PhantomData;

  use halo2_gadgets::poseidon::primitives::{Spec, Mds, generate_constants};    
  use halo2_proofs::{arithmetic::Field, circuit::{Value, SimpleFloorPlanner}, plonk::Circuit, dev::MockProver, pasta::Fp};

  use super::{PoseidonConfig, PoseidonChip};

  struct PoseidonCircuit<
    F: Field, 
    S: Spec<F,WIDTH,RATE>,
    const WIDTH: usize,
    const RATE: usize> {
      hash_input: [Value<F>; 2],
      _spec: PhantomData<S>
  }


impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize> Circuit<Fp> for PoseidonCircuit<Fp, S, WIDTH, RATE> {
  type Config = PoseidonConfig<WIDTH, RATE>;
  type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
          hash_input: (0..2)
              .map(|_i| Value::unknown())
              .collect::<Vec<Value<Fp>>>()
              .try_into()
              .unwrap(),
          _spec: PhantomData,
        }
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<Fp>) -> Self::Config {
      let hash_inputs = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
      PoseidonChip::<Fp, MySpec<WIDTH, RATE>, WIDTH, RATE>::configure(meta, hash_inputs)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl halo2_proofs::circuit::Layouter<Fp>) -> Result<(), halo2_proofs::plonk::Error> {
      let poseidon_chip = PoseidonChip::<Fp, S, WIDTH, RATE>::construct(config);
      let assigned_input_cells = poseidon_chip.load_private_inputs(
          layouter.namespace(|| "load private inputs"),
          self.hash_input,
      )?;

      poseidon_chip.hash(
        layouter.namespace(|| "poseidon chip"),
        assigned_input_cells,
      )?;
      Ok(())
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

  #[cfg(not(target_family = "wasm"))]
  fn draw_circuit<const WIDTH: usize, const RATE: usize>(k: u32, circuit: &PoseidonCircuit<Fp, MySpec<WIDTH, RATE>, WIDTH, RATE>) {
      use plotters::prelude::*;
      let base = BitMapBackend::new("img/poseidon_chip_2_inputs_no_instance.png", (1600,1600)).into_drawing_area();
      base.fill(&WHITE).unwrap();
      let base = base.titled("Poseidon Circuit", ("sans-serif", 24)).unwrap();

      halo2_proofs::dev::CircuitLayout::default()
      .mark_equality_cells(true)
          .show_equality_constraints(true)
          .render(k, circuit, &base)
          .unwrap();
  }

  #[test]
  fn test_poseidon() {
      let hash_input = [
          Fp::from(1234567u64),
          Fp::from(67890u64),
      ];

      const WIDTH: usize = 3;
      const RATE: usize = 2;
      const L: usize = 2;
      const K: u32 = 7;

      assert_eq!(hash_input.len(), L);
      assert_eq!(WIDTH, hash_input.len() + 1);
      assert_eq!(RATE, hash_input.len());

      let circuit = PoseidonCircuit::<Fp, MySpec<WIDTH, RATE>, WIDTH, RATE> {
          hash_input: hash_input.map(Value::known),
          _spec: PhantomData,
      };

      draw_circuit(K, &circuit);
      
      let correct_prover = MockProver::run(K, &circuit, vec![]).unwrap();
      correct_prover.assert_satisfied();
      assert_eq!(correct_prover.verify(), Ok(()));
  }
}