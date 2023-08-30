# Developing with Halo2

## Circuits & Chips
A circuit can have multiple chips.
A chip can have multiple gates and also contain other chips. And basically a chip is a set of constraints on a region, and a gate is a set of constraints. 

## Gate
What you define in a gate, like for example snippet below, is the set of constraints you enforce upon a certain area of cells. We call it a gate because that's how we think about computation. 

"Gate" = a series of constraints defined for an area of cells. 

```rust
meta.create_gate("accumulator constraint", |meta| {
    let s = meta.query_selector(selector);
    let username = meta.query_advice(username_column, Rotation::cur());
    let username_accumulator =
        meta.query_advice(username_accumulator_column, Rotation::cur());
    let prev_username_accumulator =
        meta.query_advice(username_accumulator_column, Rotation::prev());

    // ...

    vec![
        s.clone() * (username + prev_username_accumulator - username_accumulator),
        s * (balance + prev_balance_accumulator - balance_accumulator),
    ]
});
```