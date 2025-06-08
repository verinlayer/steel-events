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

use alloy_primitives::{address, Address};
use alloy_sol_types::{sol, SolEvent, SolValue, SolCall};
use anyhow::{Context, Result};
use clap::Parser;
use events_methods::EVENTS_ELF;
use risc0_steel::alloy::{
    network::EthereumWallet,
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    // sol_types::{SolCall, SolValue},
};
use risc0_steel::{
    ethereum::{EthEvmEnv, ETH_SEPOLIA_CHAIN_SPEC},
    Commitment, Event, SteelVerifier,
};
use risc0_zkvm::{default_executor, ExecutorEnv};
use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;

sol! {
    /// ERC-20 transfer event signature.
    /// This must match the signature in the guest.
    #[derive(Debug)]
    interface IERC20 {
        event Transfer(address indexed from, address indexed to, uint256 value);
    }
}

/// Address of the deployed contract to call the function on (USDT contract on Mainnet).
// const CONTRACT: Address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");
const CONTRACT: Address = address!("fe7087098678f792F8B98d821460B885f68B471e");
// const block_numbers: [u64; 2] = [8343938, 8494302,8495925];
const block_numbers: [u64; 2] = [8499949,8499951];

sol! {
    /// ABI-encodable journal.
    struct Journal {
        Commitment commitment;
        // bytes32 blockHash;
        uint256 value;
    }
}

/// Simple program to show the use of Ethereum contract data inside the guest.
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// URL of the RPC endpoint
    #[arg(short, long, env = "RPC_URL")]
    rpc_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::parse();

    // let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        // .wallet(wallet)
        .on_http(args.rpc_url);

    let mut env_builder = ExecutorEnv::builder();
    env_builder.write(&block_numbers.len()).unwrap();

    for i in 0..block_numbers.len() {
        let builder = EthEvmEnv::builder()
         .provider(provider.clone())
        .block_number(block_numbers[i]);
        // #[cfg(any(feature = "beacon", feature = "history"))]
        // let builder = builder.beacon_api(args.beacon_api_url);
        // #[cfg(feature = "history")]
        // let builder = builder.commitment_block_number_or_tag(args.commitment_block);

        let mut env = builder.build().await?;
        //  The `with_chain_spec` method is used to specify the chain configuration.
        env = env.with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);

        let event = Event::preflight::<IERC20::Transfer>(&mut env);
        let logs = event.address(CONTRACT).query().await?;
        log::info!(
            "Contract {} emitted {} events with signature: {}",
            CONTRACT,
            logs.len(),
            IERC20::Transfer::SIGNATURE,
        );

        let commitment_input1 = env.commitment();

        if i <= block_numbers.len() - 2 {
            log::info!("host - verify previous commitment...");
            // Create another EVM environment
            let builder1 = EthEvmEnv::builder()
                .provider(provider.clone())
                .block_number(block_numbers[i + 1]);

            let mut env1 = builder1.build().await?;
            env1 = env1.with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);

            // Preflight the verification of the commitment of the previous input.
            SteelVerifier::preflight(&mut env1)
                .verify(&commitment_input1)
                .await?;
        } else {
            log::info!(" no need to verify the commitment of the previous input, as it is not the last input.");
        }

        // Finally, construct the input from the environment.
        let evm_input = env.into_input().await?;
        env_builder.write(&evm_input).unwrap();

        if i == block_numbers.len() - 1 {
            log::info!("host - Final input processed, committing journal...");
            // If this is the last block, execute and commit
            let session_info = {
                let env = env_builder.build()
                    .context("failed to build env")?;

                let exec = default_executor();
                exec.execute(env, EVENTS_ELF)
                    .context("failed to run executor")
            }
            .context("failed to execute guest")?;

            // The journal should be the ABI encoded commitment.
            let journal = Journal::abi_decode(session_info.journal.as_ref(), true)
                .context("failed to decode journal")?;
            log::debug!("Steel commitment: {:?}", journal.commitment);

            log::info!(
                "Total USDT transferred in block {}: {}",
                block_numbers[i],
                journal.value,
            );
        }
    }
    Ok(())
}