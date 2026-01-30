import { task } from 'hardhat/config'
import { HardhatRuntimeEnvironment } from 'hardhat/types'
import { saveDeployment } from './utils'

// Task to deploy the EncryptedRPS contract
task('deploy-rps', 'Deploy the EncryptedRPS contract to the selected network').setAction(async (_, hre: HardhatRuntimeEnvironment) => {
    const { ethers, network } = hre

    console.log(`Deploying EncryptedRPS to ${network.name}...`)

    // Get the deployer account
    const [deployer] = await ethers.getSigners()
    console.log(`Deploying with account: ${deployer.address}`)

    // Deploy the contract
    const EncryptedRPS = await ethers.getContractFactory('EncryptedRPS')
    const rps = await EncryptedRPS.deploy()
    await rps.waitForDeployment()

    const rpsAddress = await rps.getAddress()
    console.log(`EncryptedRPS deployed to: ${rpsAddress}`)

    // Save the deployment
    saveDeployment(network.name, 'EncryptedRPS', rpsAddress)

    return rpsAddress
})
