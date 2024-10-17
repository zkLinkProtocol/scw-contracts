import * as dotenv from "dotenv";

import { HardhatUserConfig, task } from "hardhat/config";

import "@nomiclabs/hardhat-etherscan";
import "@nomiclabs/hardhat-waffle";
import "@typechain/hardhat";
import "hardhat-gas-reporter";
import "solidity-coverage";
import "hardhat-deploy";
import "@nomiclabs/hardhat-ethers";
import "hardhat-dependency-compiler";
import { parseUnits } from "ethers/lib/utils";

const walletUtils = require("./walletUtils");

dotenv.config();

const shouldRunInForkMode = !!process.env.FORK_MODE;

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
task("accounts", "Prints the list of accounts", async (taskArgs, hre) => {
  const accounts = await hre.ethers.getSigners();

  for (const account of accounts) {
    console.log(account.address);
  }
});

const hardhatAccounts =
  process.env.PRIVATE_KEY !== undefined
    ? [process.env.PRIVATE_KEY]
    : walletUtils.makeKeyList();

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

const config: HardhatUserConfig = {
  paths: {
    artifacts: "artifacts",
    cache: "cache",
    deploy: "src/deploy",
    sources: "contracts",
  },
  namedAccounts: {
    deployer: 0,
    verifiedSigner: 5,
  },
  solidity: {
    compilers: [
      {
        version: "0.8.17",
        settings: {
          optimizer: { enabled: true, runs: 800 },
          viaIR: true,
        },
      },
    ],
  },
  networks: {
    hardhat: {
      ...(shouldRunInForkMode
        ? {
          // Forking Config for Deployment Testing
          chainId: 5000,
          forking: {
            url: process.env.MANTLE_MAINNET_URL,
          },
          accounts: [
            {
              privateKey: process.env.PRIVATE_KEY!,
              // This is a dummy value and will be overriden in the test by
              // the account's actual balance from the forked chain
              balance: "10000000000000000000000000",
            },
          ],
        }
        : {
          // Normal Config
          accounts: {
            accountsBalance: "10000000000000000000000000",
            //   mnemonic: MNEMONIC,
          },
          allowUnlimitedContractSize: true,
          chainId: 31337,
        }),
    },
    hardhat_node: {
      live: false,
      saveDeployments: false,
      chainId: 31337,
      url: "http://localhost:8545",
    },
    local: {
      live: false,
      saveDeployments: false,
      chainId: 1337,
      url: "http://localhost:8545",
      accounts: {
        mnemonic:
          "garbage miracle journey siren inch method pulse learn month grid frame business",
        path: "m/44'/60'/0'/0",
        initialIndex: 0,
        count: 20,
      },
      gasPrice: parseUnits("1", "gwei").toNumber(),
    },
    mainnet: {
      url: process.env.ETH_MAINNET_URL || "",
      chainId: 1,
      accounts: hardhatAccounts,
    },
    sepolia: {
      url: process.env.SEPOLIA_URL || "",
      chainId: 11155111,
      accounts: hardhatAccounts,
    },
    arbitrumOne: {
      url: "https://arb1.arbitrum.io/rpc",
      accounts: hardhatAccounts,
      chainId: 42161,
    },
    arbitrumSepolia: {
      url: "https://sepolia-rollup.arbitrum.io/rpc",
      accounts: hardhatAccounts,
      chainId: 421614,
    },
    optimismMainnet: {
      url: `https://mainnet.optimism.io`,
      accounts: hardhatAccounts,
      chainId: 10,
    },
    optimismSepolia: {
      url: `https://sepolia.optimism.io`,
      accounts: hardhatAccounts,
      chainId: 11155420,
    },
    baseMainnet: {
      url:
        process.env.BASE_MAINNET_URL ||
        `https://developer-access-mainnet.base.org`,
      accounts: hardhatAccounts,
      chainId: 8453,
    },
    baseSepolia: {
      url: "https://sepolia.base.org",
      chainId: 84532,
      accounts: hardhatAccounts,
    },
    lineaMainnet: {
      url: process.env.LINEA_MAINNET_URL || ``,
      accounts: hardhatAccounts,
      chainId: 59144,
    },
    lineaSepolia: {
      url: process.env.LINEA_SEPOLIA_URL || `https://rpc.sepolia.linea.build`,
      accounts: hardhatAccounts,
      chainId: 59141,
    },
    mantaMainnet: {
      url: process.env.MANTA_MAINNET_URL || "",
      accounts: hardhatAccounts,
      chainId: 169,
    },
    mantaSepolia: {
      url: process.env.MANTA_TESTNET_URL || "",
      accounts: hardhatAccounts,
      chainId: 3441006,
    },
    scrollMainnet: {
      url: process.env.SCROLL_MAINNET_URL || "",
      accounts: hardhatAccounts,
      chainId: 534352,
    },
    scrollSepolia: {
      url: process.env.SCROLL_TESTNET_URL || "",
      accounts: hardhatAccounts,
      chainId: 534351,
    },
  },

  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
    onlyCalledMethods: true,
  },

  dependencyCompiler: {
    paths: ["@account-abstraction/contracts/core/EntryPoint.sol"],
  },
  etherscan: {
    apiKey: {
      mainnet: process.env.ETHERSCAN_API_KEY || "",
      sepolia: process.env.ETHERSCAN_API_KEY || "",
      arbitrumOne: process.env.ARBITRUM_API_KEY || "",
      arbitrumSepolia: process.env.ARBITRUM_API_KEY || "",
      optimismMainnet: process.env.OPTIMISM_API_KEY || "",
      optimismSepolia: process.env.OPTIMISM_API_KEY || "",
      lineaMainnet: process.env.LINEA_API_KEY || "",
      lineaSepolia: process.env.LINEA_API_KEY || "",
      baseMainnet: process.env.BASE_API_KEY || "",
      baseSepolia: process.env.BASE_API_KEY || "",
      mantaMainnet: process.env.MANTA_API_KEY || "",
      mantaSepolia: process.env.MANTA_API_KEY || "",
      scrollMainnet: process.env.SCROLL_API_KEY || "",
      scrollSepolia: process.env.SCROLL_API_KEY || "",
    },
    customChains: [
      {
        "network": "optimismMainnet",
        "chainId": 10,
        "urls": {
          "apiURL": "https://api-optimistic.etherscan.io/api",
          "browserURL": "https://optimistic.etherscan.io"
        }
      },
      {
        "network": "optimismSepolia",
        "chainId": 11155420,
        "urls": {
          "apiURL": "https://api-sepolia-optimistic.etherscan.io/api",
          "browserURL": "https://sepolia-optimistic.etherscan.io"
        }
      },
      {
        network: "lineaSepolia",
        chainId: 59141,
        urls: {
          apiURL: "https://api-sepolia.lineascan.build/api",
          browserURL: "https://sepolia.lineascan.build/",
        },
      },
      {
        network: "lineaMainnet",
        chainId: 59144,
        urls: {
          apiURL: "https://api.lineascan.build/api",
          browserURL: "https://lineascan.build",
        },
      },
      {
        network: "baseMainnet",
        chainId: 8453,
        urls: {
          apiURL: "https://api.basescan.org/api",
          browserURL: "https://basescan.org",
        },
      },
      {
        network: "baseSepolia",
        chainId: 84532,
        urls: {
          apiURL: "https://api-sepolia.basescan.org/api",
          browserURL: "https://sepolia.basescan.org"
        }
      },
      {
        network: "arbitrumSepolia",
        chainId: 421614,
        urls: {
          apiURL: "https://api-sepolia.arbiscan.io/api",
          browserURL: "	https://sepolia.arbiscan.io"
        }
      },
      {
        network: "mantaMainnet",
        chainId: 169,
        urls: {
          apiURL: "https://pacific-explorer.manta.network/api",
          browserURL: "https://pacific-explorer.manta.network/",
        },
      },
      {
        network: "mantaSepolia",
        chainId: 3441006,
        urls: {
          apiURL: "https://pacific-explorer.sepolia-testnet.manta.network/api",
          browserURL: "https://pacific-explorer.sepolia-testnet.manta.network",
        },
      },
      {
        network: 'scrollMainnet',
        chainId: 534352,
        urls: {
          apiURL: 'https://api.scrollscan.com/api',
          browserURL: 'https://scrollscan.com/',
        },
      },
      {
        network: 'scrollSepolia',
        chainId: 534351,
        urls: {
          apiURL: 'https://api-sepolia.scrollscan.com/api',
          browserURL: 'https://sepolia.scrollscan.com/',
        },
      },
    ],
  },
};

export default config;
