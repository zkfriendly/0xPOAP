// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(unused_doc_comments)]
#![allow(unused_imports)]
#![no_main]

use alloy_primitives::{address, Address, U256};
use alloy_sol_types::{sol, SolValue};
use risc0_ethereum_view_call::{config::GNOSIS_CHAIN_SPEC, ethereum::EthViewCallInput, ViewCall};
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);

sol! {
    interface POAP {
        function tokenDetailsOfOwnerByIndex(address owner, uint256 index) external view returns (uint256, uint256);
    }
}

use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};
const CONTRACT: Address = address!("22C1f6050E56d2876009903609a2cC3fEf83B415");

use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{parameters::bn254_x5, Poseidon, PoseidonHasher};
use ark_bn254::Fr;


fn main() {
    // Read the input from the guest environment.
    // let call_input: EthViewCallInput = env::read();
    // let (encoded_verifying_key, message, signature): (EncodedPoint, Vec<u8>, Signature) =
    //     env::read();
    // let verifying_key = VerifyingKey::from_encoded_point(&encoded_verifying_key).unwrap();

    // // Verify the signature.
    // verifying_key.verify(&message, &signature).expect("Signature verification failed");

    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();

    let input1 = Fr::from_be_bytes_mod_order(&[1u8; 32]);
    let input2 = Fr::from_be_bytes_mod_order(&[2u8; 32]);

    let hash = poseidon.hash(&[input1, input2]).unwrap();

    println!("Poseidon hash: {}", hash);

    // Get the caller address from the verifying key.
    // let caller = Address::from_public_key(&verifying_key);

    // let call: POAP::tokenDetailsOfOwnerByIndexCall =
    //     POAP::tokenDetailsOfOwnerByIndexCall { owner: caller, index: <U256>::from(0) };

    // // Converts the input into a `ViewCallEnv` for execution. The `with_chain_spec` method is used
    // // to specify the chain configuration. It checks that the state matches the state root in the
    // // header provided in the input.
    // let view_call_env = call_input.into_env().with_chain_spec(&GNOSIS_CHAIN_SPEC);
    // // Commit the block hash and number used when deriving `view_call_env` to the journal.
    // env::commit_slice(&view_call_env.block_commitment().abi_encode());

    // // Execute the view call; it returns the result in the type generated by the `sol!` macro.
    // let returns = ViewCall::new(call, CONTRACT).with_caller(caller).execute(view_call_env);
    // println!("View call result: {} , {}", returns._0, returns._1);
}
