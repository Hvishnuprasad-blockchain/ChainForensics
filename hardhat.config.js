import "dotenv/config";
import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import hardhatNode from "./node_modules/hardhat/dist/src/internal/builtin-plugins/node/index.js";

const networks = {
    localhost: {
        type: "http",
        chainType: "l1",
        url: "http://127.0.0.1:8545",
    },
};

if (process.env.SEPOLIA_RPC_URL) {
    networks.sepolia = {
        type: "http",
        chainType: "l1",
        url: process.env.SEPOLIA_RPC_URL,
        accounts: process.env.SEPOLIA_PRIVATE_KEY
            ? [process.env.SEPOLIA_PRIVATE_KEY]
            : [],
    };
}

export default defineConfig({
    plugins: [hardhatToolboxMochaEthers, hardhatNode],

    solidity: {
        version: "0.8.19",
    },

    networks,

    test: {
        mocha: {
            timeout: 120000,
        },
    },
});