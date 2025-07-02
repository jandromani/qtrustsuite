// scripts/deploy.js
const hre = require("hardhat");      // Runtime env
const { ethers } = hre;

async function main() {
  const HashAnchor = await ethers.getContractFactory("HashAnchor");
  const hashAnchor = await HashAnchor.deploy();       // constructor sin args
  await hashAnchor.waitForDeployment();               // Hardhat ≥2.19
  console.log("HashAnchor deployed to:", hashAnchor.target);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
