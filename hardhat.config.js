// hardhat.config.js
/** @type import('hardhat/config').HardhatUserConfig */

// 1️⃣  Plugins que quieres usar
require("@nomicfoundation/hardhat-toolbox");   // incluye hardhat-ethers, chai, etc.
// Si prefieres lo mínimo:  require("@nomicfoundation/hardhat-ethers");

module.exports = {
  solidity: "0.8.28",

  // 2️⃣  Redes disponibles
  networks: {
    hardhat: {},                // la interna
    localhost: {                // la que levanta `npx hardhat node`
      url: "http://127.0.0.1:8545",
      accounts: [
        // Private Key de la cuenta #0 que te da Hardhat
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
      ]
    }
  }
};
