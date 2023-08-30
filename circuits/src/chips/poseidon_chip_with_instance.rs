use std::marker::PhantomData;

use halo2_proofs::{arithmetic::Field, plonk::{Advice, Column, Instance, ConstraintSystem, Fixed, Error}, circuit::{Chip, Layouter, AssignedCell, Value}, pasta::{Fp, group::ff::PrimeField, self}};
use halo2_gadgets::poseidon::{Pow5Chip, Pow5Config, primitives::{Spec, ConstantLength}, Hash};

/// WIP Poseidon Chip with L hash inputs
/// TODO Doesn't fully compile for L arbitrary yet
/// Examples that were used:
/// https://github.com/summa-dev/halo2-experiments/blob/9293898f3136f5b16b621f66c9787e437461dd75/src/chips/poseidon/hash.rs
/// https://github.com/summa-dev/halo2-experiments/blob/main/src/chips/poseidon/hash_with_instance.rs
/// https://github.com/summa-dev/halo2-experiments/blob/main/src/circuits/poseidon.rs
/// 
#[derive(Clone, Debug)]
pub struct PoseidonConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
  inputs: Vec<Column<Advice>>,
  expected_output: Column<Instance>, // hash output
  pow5_config: Pow5Config<pasta::Fp, WIDTH, RATE> // halo2 gadget which is configured correctly to be used as a PoseidonChip instance
}

#[derive(Clone, Debug)]
pub struct PoseidonChip<
    F: Field,
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize> {
      config: PoseidonConfig<WIDTH, RATE, L>,
      _marker: PhantomData<(F, S)>
}

impl<F: Field, S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> Chip<F> for PoseidonChip<F, S, WIDTH, RATE, L> {
    type Config = PoseidonConfig<WIDTH, RATE, L>;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field, S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> PoseidonChip<F, S, WIDTH, RATE, L> {

  pub fn construct(config: PoseidonConfig<WIDTH, RATE, L>) -> Self{
    Self {
      config,
      _marker: PhantomData
    }
  }

  pub fn configure(
    meta: &mut ConstraintSystem<Fp>, 
    inputs: Vec<Column<Advice>>, 
    expected_output: Column<Instance>) -> PoseidonConfig<WIDTH, RATE, L> {

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

    // The expected outcome should be comparable to pub input
    meta.enable_equality(expected_output);
    meta.enable_constant(rc_b[0]);//Apparently this is needed

    PoseidonConfig {
      inputs: inputs.clone(),
      expected_output,
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
    inputs: [Value<F>; L]
  ) -> Result<[AssignedCell<F, F>; 2], Error> { // TODO how to make the whole flow compile with L instead of 2?
    layouter.assign_region(
        || "load private inputs",
        |mut region| -> Result<[AssignedCell<F, F>; L], Error> {
            let result = inputs
                .iter()
                .enumerate()
                .map(|(i, x)| {
                    region.assign_advice(
                        || "val",
                        self.config.inputs[i],
                        0,
                        || *x,
                    )
                })
                .collect::<Result<Vec<AssignedCell<F, F>>, Error>>();
            Ok(result?.try_into().unwrap())
        },
    ).map(|res| {
      // to make it compile
      let short_array: [AssignedCell<F,F>; 2] = [res.get(0).unwrap().clone(), res.get(1).unwrap().clone()];
      short_array
    })
  }

  pub fn hash(
      &self, 
      mut layouter: impl Layouter<Fp>,
      input_cells: [AssignedCell<Fp,Fp>; 2] // TODO how to make the whole flow wrk with L instead of 2
    ) -> Result<AssignedCell<Fp,Fp>, Error> {
      let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());

      let hasher = Hash::<_, _, S, ConstantLength<2>, WIDTH, RATE>::init(
        pow5_chip,
          layouter.namespace(|| "hasher"),
      )?;
      hasher.hash(layouter.namespace(|| "hash"), input_cells)
  }

  pub fn expose_public(
    &self,
    mut layouter: impl Layouter<F>,
    cell: &AssignedCell<F, F>,
    row: usize,
  ) -> Result<(), Error> {
      layouter.constrain_instance(cell.cell(), self.config.expected_output, row)
  }
}


#[cfg(test)]
mod tests {
  use std::marker::PhantomData;

  use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3, Spec, Mds, generate_constants};    
  use halo2_proofs::{arithmetic::Field, circuit::{Value, SimpleFloorPlanner}, plonk::Circuit, dev::MockProver, pasta::Fp};

  use super::{PoseidonConfig, PoseidonChip};

  struct PoseidonCircuitWithInstance<
    F: Field, 
    S: Spec<F,WIDTH,RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize> {
      hash_input: [Value<F>; L],
      _spec: PhantomData<S>
  }


  impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fp> for PoseidonCircuitWithInstance<Fp, S, WIDTH, RATE, L> {
    type Config = PoseidonConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
          hash_input: (0..L)
              .map(|_i| Value::unknown())
              .collect::<Vec<Value<Fp>>>()
              .try_into()
              .unwrap(),
          _spec: PhantomData,
        }
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<Fp>) -> Self::Config {
      let hash_inputs = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
      let output = meta.instance_column();
      PoseidonChip::<Fp, MySpec<WIDTH, RATE>, WIDTH, RATE, L>::configure(meta, hash_inputs, output)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl halo2_proofs::circuit::Layouter<Fp>) -> Result<(), halo2_proofs::plonk::Error> {
      let poseidon_chip = PoseidonChip::<Fp, S, WIDTH, RATE, L>::construct(config);
      let assigned_input_cells = poseidon_chip.load_private_inputs(
          layouter.namespace(|| "load private inputs"),
          self.hash_input,
      )?;

      let digest = poseidon_chip.hash(
        layouter.namespace(|| "poseidon chip"),
        assigned_input_cells,
      )?;
      poseidon_chip.expose_public(layouter.namespace(|| "expose result"), &digest, 0)?;
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

  // Draws the layout of the circuit. Super useful for debugging.
  #[cfg(not(target_family = "wasm"))]
  fn draw_circuit<const WIDTH: usize, const RATE: usize, const L: usize>(k: u32, circuit: &PoseidonCircuitWithInstance<Fp, MySpec<WIDTH, RATE>, WIDTH, RATE, L>) {
      use plotters::prelude::*;
      let base = BitMapBackend::new("poseidon_w_instance_circuit.png", (1600,1600)).into_drawing_area();
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
          Fp::from(234872304u64),
          Fp::from(11111u64)
      ];

      const WIDTH: usize = 3;
      const RATE: usize = 2;
      const L: usize = 2;

      assert_eq!(hash_input.len(), L);
      assert_eq!(WIDTH, hash_input.len() + 1);
      assert_eq!(RATE, hash_input.len());

      const K: u32 = 7;

      let correct_digest = poseidon::Hash::<_, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init()
              .hash(hash_input);
            
      let wrong_digest = poseidon::Hash::<_, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init()
              .hash([Fp::from(10u64), Fp::from(12u64)]);

      let circuit = PoseidonCircuitWithInstance::<Fp, MySpec<WIDTH, RATE>, WIDTH, RATE, L> {
          hash_input: hash_input.map(Value::known),
          _spec: PhantomData,
      };

      draw_circuit(K, &circuit);
      
      let correct_prover = MockProver::run(K, &circuit, vec![vec![correct_digest]]).unwrap();
      correct_prover.assert_satisfied();
      assert_eq!(correct_prover.verify(), Ok(()));

      let wrong_prover = MockProver::run(K, &circuit, vec![vec![wrong_digest]]).unwrap();
      assert!(wrong_prover.verify().is_err());
  }
}