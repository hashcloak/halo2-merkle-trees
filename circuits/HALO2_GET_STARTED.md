# Halo2 practice

## Resources

Halo2 book
https://zcash.github.io/halo2/index.html

Excellent resource for practice and Halo2 examples with increasing difficulty is this repo: https://github.com/summa-dev/halo2-experiments/tree/main

### Helpful Presentations/Workshops

[Little Things I’ve Learned in Developing Halo2 Circuits by Chih-Cheng Liang | Devcon Bogotá](https://www.youtube.com/watch?v=wSfkpJDq8AI) (how do you think like a circuit dev)

[Design a Proof Of Solvency protocol with Halo2 Workshop by Enrico: Zcon4](https://www.youtube.com/watch?v=P7w6LWXkwns). This is the person that worked on the summa-dev examples repo. 

## Tip

Halo2 offers the possibility to print the layout of the circuit, which helps a lot with understanding chip/circuit layout and finding bugs.

See example in `poseidon_chip_2_inputs.rs`; in the tests there is function `draw_circuit` which creates a png in the `img` folder with the representation of the circuit. 

## Errors

NotEnoughRows available: increase k. 