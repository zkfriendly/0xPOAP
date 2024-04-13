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

use std::collections::BTreeMap;
#[allow(unused_imports)]
use alloy_primitives::{address, Address};
use alloy_sol_types::{sol, SolCall, SolValue};
use anyhow::{Context, Result};
use clap::Parser;
use erc20_methods::ERC20_GUEST_ELF;
use k256::{
    ecdsa::{
        signature::{Keypair, Signer},
        Signature, SigningKey, VerifyingKey,
    },
    EncodedPoint,
};
use risc0_ethereum_view_call::{
    config::ETH_SEPOLIA_CHAIN_SPEC, ethereum::EthViewCallEnv, EvmHeader, ViewCall,
};

use rand_core::OsRng;
use risc0_ethereum_view_call::config::{ChainSpec, EIP1559_CONSTANTS_DEFAULT, ForkCondition};
use risc0_zkvm::{default_executor, ExecutorEnv, SessionInfo};
use tracing_subscriber::EnvFilter;

/// Address of the USDT contract on Ethereum Sepolia
const CONTRACT: Address = address!("4ECaBa5870353805a9F068101A40E0f32ed605C6");
/// Function to call
const CALL: IERC20::balanceOfCall =
    IERC20::balanceOfCall { account: address!("ba12222222228d8ba445958a75a0704d566bf2c8") };
/// Caller address
const CALLER: Address = address!("ba12222222228d8ba445958a75a0704d566bf2c8");

sol! {
    /// ERC-20 balance function signature.
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

/// Simple program to show the use of Ethereum contract data inside the guest.
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// URL of the RPC endpoint
    #[arg(short, long, env = "RPC_URL")]
    rpc_url: String,
}

/// Given an secp256k1 verifier key (i.e. public key), message and signature,
/// runs the ECDSA verifier inside the zkVM and returns a receipt, including a
/// journal and seal attesting to the fact that the prover knows a valid
/// signature from the committed public key over the committed message.
fn prove_ecdsa_verification(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<SessionInfo> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    // parse the command line arguments
    let args = Args::parse();

    // Create a view call environment from an RPC endpoint and a block number. If no block number is
    // provided, the latest block is used. The `with_chain_spec` method is used to specify the
    // chain configuration.
    let env =
        EthViewCallEnv::from_rpc(&args.rpc_url, None)?.with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);
    let number = env.header().number();
    let commitment = env.block_commitment();

    // Preflight the view call to construct the input that is required to execute the function in
    // the guest. It also returns the result of the call.
    let (input, returns) = ViewCall::new(CALL, CONTRACT).with_caller(CALLER).preflight(env)?;
    println!("For block {} `{}` returns: {}", number, IERC20::balanceOfCall::SIGNATURE, returns._0);

    let sig_data_inputs = (verifying_key.to_encoded_point(true), message, signature);

    println!("Running the guest with the constructed input:");
    let session_info = {
        let env = ExecutorEnv::builder()
            .write(&input)
            .unwrap()
            .write(&sig_data_inputs)
            .unwrap()
            .build()
            .context("Failed to build exec env")?;
        let exec = default_executor();
        exec.execute(env, ERC20_GUEST_ELF).context("failed to run executor")?
    };

    Ok(session_info)
}

fn main() -> Result<()> {
    let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
    let message = b"This is a message that will be signed, and verified within the zkVM";
    let signature: Signature = signing_key.sign(message);
    let session_info =
        prove_ecdsa_verification(signing_key.verifying_key(), message, &signature).unwrap();

    println!("Proof generated successfully! {}", session_info.journal.as_ref().len());

    Ok(())

    // // extract the proof from the session info and validate it
    // let bytes = session_info.journal.as_ref();
    // assert_eq!(&bytes[..64], &commitment.abi_encode());

    // Ok(())
}
