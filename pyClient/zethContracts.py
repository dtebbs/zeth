import json
import os
import sys

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
from web3.contract import ConciseContract
from solcx import compile_standard, compile_files

# Get the utils written to interact with the prover
# and access the formatting utils
import zethGRPC

# Import the constants defined for zeth
import zethConstants as constants
# Import zeth standard error messages
import zethErrors as errors

w3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))

# Returns the files to use for the given zkSNARK (verifier_contract, mixer_contract)
def get_zksnark_files(zksnark):
    if zksnark == constants.PGHR13_ZKSNARK:
        return (constants.PGHR13_VERIFIER_CONTRACT, constants.PGHR13_MIXER_CONTRACT)
    elif zksnark == constants.GROTH16_ZKSNARK:
        return (constants.GROTH16_VERIFIER_CONTRACT, constants.GROTH16_MIXER_CONTRACT)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)

def compile_contracts(zksnark):
    contracts_dir = os.environ['ZETH_CONTRACTS_DIR']
    (verifier_name, mixer_name) = get_zksnark_files(zksnark)

    path_to_verifier = os.path.join(contracts_dir, verifier_name + ".sol")
    path_to_mixer = os.path.join(contracts_dir, mixer_name + ".sol")
    compiled_sol = compile_files([path_to_verifier, path_to_mixer])
    verifier_interface = compiled_sol[path_to_verifier + ':' + verifier_name]
    mixer_interface = compiled_sol[path_to_mixer + ':' + mixer_name]
    return (verifier_interface, mixer_interface)

def compile_util_contracts():
    contracts_dir = os.environ['ZETH_CONTRACTS_DIR']
    path_to_pairing = os.path.join(contracts_dir, "Pairing.sol")
    path_to_bytes = os.path.join(contracts_dir, "Bytes.sol")
    compiled_sol = compile_files([path_to_pairing, path_to_bytes])

# Deploy the verifier used with PGHR13
def deploy_pghr13_verifier(vk, verifier, deployer_address, deployment_gas):
    # Deploy the verifier contract with the good verification key
    tx_hash = verifier.constructor(
        A1=zethGRPC.hex2int(vk["a"][0]),
        A2=zethGRPC.hex2int(vk["a"][1]),
        B=zethGRPC.hex2int(vk["b"]),
        C1=zethGRPC.hex2int(vk["c"][0]),
        C2=zethGRPC.hex2int(vk["c"][1]),
        gamma1=zethGRPC.hex2int(vk["g"][0]),
        gamma2=zethGRPC.hex2int(vk["g"][1]),
        gammaBeta1=zethGRPC.hex2int(vk["gb1"]),
        gammaBeta2_1=zethGRPC.hex2int(vk["gb2"][0]),
        gammaBeta2_2=zethGRPC.hex2int(vk["gb2"][1]),
        Z1=zethGRPC.hex2int(vk["z"][0]),
        Z2=zethGRPC.hex2int(vk["z"][1]),
        IC_coefficients=zethGRPC.hex2int(sum(vk["IC"], []))
    ).transact({'from': deployer_address, 'gas': deployment_gas})

    # Get tx receipt to get Verifier contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    verifier_address = tx_receipt['contractAddress']
    return verifier_address

# Common function to deploy a mixer contract
# Returns the mixer and the initial merkle root of the commitment tree
def deploy_mixer(verifier_address, mixer_interface, mk_tree_depth, deployer_address, deployment_gas, token_address):
    # Deploy the Mixer contract once the Verifier is successfully deployed
    mixer = w3.eth.contract(abi=mixer_interface['abi'], bytecode=mixer_interface['bin'])
    tx_hash = mixer.constructor(
        verifier_address = verifier_address,
        mk_depth = mk_tree_depth,
        token_address = token_address
    ).transact({'from': deployer_address, 'gas': deployment_gas})
    # Get tx receipt to get Mixer contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    mixer_address = tx_receipt['contractAddress']
    # Get the mixer contract instance
    mixer = w3.eth.contract(
        address=mixer_address,
        abi=mixer_interface['abi']
    )
    # Get the initial merkle root to proceed to the first payments
    ef_logMerkleRoot = mixer.eventFilter("LogMerkleRoot", {'fromBlock': 'latest'})
    event_logs_logMerkleRoot = ef_logMerkleRoot.get_all_entries()
    initialRoot = w3.toHex(event_logs_logMerkleRoot[0].args.root)
    return(mixer, initialRoot[2:])

def deploy_pghr13_contracts(vk_json, mk_tree_depth, verifier, mixer_interface, deployer_address, deployment_gas, token_address):
    verifier_address = deploy_pghr13_verifier(vk_json, verifier, deployer_address, deployment_gas)
    return deploy_mixer(verifier_address, mixer_interface, mk_tree_depth, deployer_address, deployment_gas, token_address)

# Deploy the verifier and the mixer used with GROTH16
def deploy_groth16_verifier(vk, verifier, deployer_address, deployment_gas):
    # Deploy the verifier contract with the good verification key
    tx_hash = verifier.constructor(
        Alpha=zethGRPC.hex2int(vk["alpha_g1"]),
        Beta1=zethGRPC.hex2int(vk["beta_g2"][0]),
        Beta2=zethGRPC.hex2int(vk["beta_g2"][1]),
        Gamma1=zethGRPC.hex2int(vk["gamma_g2"][0]),
        Gamma2=zethGRPC.hex2int(vk["gamma_g2"][1]),
        Delta1=zethGRPC.hex2int(vk["delta_g2"][0]),
        Delta2=zethGRPC.hex2int(vk["delta_g2"][1]),
        Gamma_ABC_coords=zethGRPC.hex2int(sum(vk["gamma_abc_g1"], []))
    ).transact({'from': deployer_address, 'gas': deployment_gas})

    # Get tx receipt to get Verifier contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    verifier_address = tx_receipt['contractAddress']
    return verifier_address

def deploy_groth16_contracts(vk_json, mk_tree_depth, verifier, mixer_interface, deployer_address, deployment_gas, token_address):
    verifier_address = deploy_groth16_verifier(vk_json, verifier, deployer_address, deployment_gas)
    return deploy_mixer(verifier_address, mixer_interface, mk_tree_depth, deployer_address, deployment_gas, token_address)

# Deploy the mixer contract with the given merkle tree depth
# and returns an instance of the mixer along with the initial merkle tree
# root to use for the first zero knowledge payments
def deploy_contracts(mk_tree_depth, verifier_interface, mixer_interface, deployer_address, deployment_gas, token_address, zksnark):
    setup_dir = os.environ['ZETH_TRUSTED_SETUP_DIR']
    vk_json = os.path.join(setup_dir, "vk.json")
    with open(vk_json) as json_data:
        vk = json.load(json_data)

    # Deploy the verifier contract with the good verification key
    verifier = w3.eth.contract(abi=verifier_interface['abi'], bytecode=verifier_interface['bin'])
    if zksnark == constants.PGHR13_ZKSNARK:
        return deploy_pghr13_contracts(vk, mk_tree_depth, verifier, mixer_interface, deployer_address, deployment_gas, token_address)
    elif zksnark == constants.GROTH16_ZKSNARK:
        return deploy_groth16_contracts(vk, mk_tree_depth, verifier, mixer_interface, deployer_address, deployment_gas, token_address)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)

# Call to the mixer's mix function to do zero knowledge payments
def mix_pghr13(
        mixer_instance,
        ciphertext1,
        ciphertext2,
        parsed_proof,
        sender_address,
        wei_pub_value,
        call_gas
    ):
    tx_hash = mixer_instance.functions.mix(
        ciphertext1,
        ciphertext2,
        zethGRPC.hex2int(parsed_proof["a"]),
        zethGRPC.hex2int(parsed_proof["a_p"]),
        [zethGRPC.hex2int(parsed_proof["b"][0]), zethGRPC.hex2int(parsed_proof["b"][1])],
        zethGRPC.hex2int(parsed_proof["b_p"]),
        zethGRPC.hex2int(parsed_proof["c"]),
        zethGRPC.hex2int(parsed_proof["c_p"]),
        zethGRPC.hex2int(parsed_proof["h"]),
        zethGRPC.hex2int(parsed_proof["k"]),
        zethGRPC.hex2int(parsed_proof["inputs"])
    ).transact({'from': sender_address, 'value': wei_pub_value, 'gas': call_gas})

    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    return parse_mix_call(mixer_instance, tx_receipt)

def mix_groth16(
        mixer_instance,
        ciphertext1,
        ciphertext2,
        parsed_proof,
        sender_address,
        wei_pub_value,
        call_gas
    ):
    tx_hash = mixer_instance.functions.mix(
        ciphertext1,
        ciphertext2,
        zethGRPC.hex2int(parsed_proof["a"]),
        [zethGRPC.hex2int(parsed_proof["b"][0]), zethGRPC.hex2int(parsed_proof["b"][1])],
        zethGRPC.hex2int(parsed_proof["c"]),
        zethGRPC.hex2int(parsed_proof["inputs"])
    ).transact({'from': sender_address, 'value': wei_pub_value, 'gas': call_gas})

    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    return parse_mix_call(mixer_instance, tx_receipt)

def mix(
        mixer_instance,
        ciphertext1,
        ciphertext2,
        parsed_proof,
        sender_address,
        wei_pub_value,
        call_gas,
        zksnark
    ):
    if zksnark == constants.PGHR13_ZKSNARK:
        return mix_pghr13(
            mixer_instance,
            ciphertext1,
            ciphertext2,
            parsed_proof,
            sender_address,
            wei_pub_value,
            call_gas
        )
    elif zksnark == constants.GROTH16_ZKSNARK:
        return mix_groth16(
            mixer_instance,
            ciphertext1,
            ciphertext2,
            parsed_proof,
            sender_address,
            wei_pub_value,
            call_gas
        )
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)

def parse_mix_call(mixer_instance, tx_receipt):
    # Get the logs data associated with this mixing
    #
    # Gather the addresses of the appended commitments
    event_filter_logAddress = mixer_instance.eventFilter("LogAddress", {'fromBlock': 'latest'})
    event_logs_logAddress = event_filter_logAddress.get_all_entries()
    # Get the new merkle root
    event_filter_logMerkleRoot = mixer_instance.eventFilter("LogMerkleRoot", {'fromBlock': 'latest'})
    event_logs_logMerkleRoot = event_filter_logMerkleRoot.get_all_entries()
    # Get the ciphertexts
    event_filter_logSecretCiphers = mixer_instance.eventFilter("LogSecretCiphers", {'fromBlock': 'latest'})
    event_logs_logSecretCiphers = event_filter_logSecretCiphers.get_all_entries()

    commitment_address1 = event_logs_logAddress[0].args.commAddr
    commitment_address2 = event_logs_logAddress[1].args.commAddr
    new_mk_root = w3.toHex(event_logs_logMerkleRoot[0].args.root)[2:] # [2:] to strip the '0x' prefix
    ciphertext1 = event_logs_logSecretCiphers[0].args.ciphertext
    ciphertext2 = event_logs_logSecretCiphers[1].args.ciphertext
    return (commitment_address1, commitment_address2, new_mk_root, ciphertext1, ciphertext2)
