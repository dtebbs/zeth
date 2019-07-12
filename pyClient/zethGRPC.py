from Crypto import Random
import os
import json
import hashlib
import sys

# Access the encoding functions
from eth_abi import encode_single, encode_abi

# Access the gRPC service and the proto messages
import grpc
from google.protobuf import empty_pb2
import util_pb2
import util_pb2_grpc
import prover_pb2
import prover_pb2_grpc

# Import the zeth constants and standard errors
import zethConstants as constants
import zethErrors as errors

# Import MiMC hash and constants
from zethMimc import MiMC7
from zethConstants import ZETH_MIMC_PRIME, ZETH_MIMC_IV_MT, ZETH_MIMC_IV_CM, ZETH_MIMC_IV_NF, ZETH_MIMC_IV_ADD

# Fetch the verification key from the proving service
def getVerificationKey(grpcEndpoint):
    with grpc.insecure_channel(grpcEndpoint) as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- Get the verification key --------------")
        verificationkey = stub.GetVerificationKey(make_empty_message())
        return verificationkey

# Request a proof generation to the proving service
def getProof(grpcEndpoint, proofInputs):
    with grpc.insecure_channel(grpcEndpoint) as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- Get the proof --------------")
        proof = stub.Prove(proofInputs)

        return proof


def hex2int(elements):
    ints = []
    for el in elements:
        ints.append(int(el, 16))
    return(ints)

def getRandomAsHex():
    return bytes(Random.get_random_bytes(32)).hex()

def noteRandomness(i, phi, hsig):
    rand_rho = computeRho(i, phi, hsig)
    rand_trapR = bytes(Random.get_random_bytes(32)).hex()
    randomness = {
        "rho": rand_rho,
        "trapR": rand_trapR
    }
    return randomness

# We follow the formatting of the proto file
def createZethNote(randomness, recipientApk, value):
    note = util_pb2.ZethNote(
        aPK=recipientApk,
        value=value,
        rho=randomness["rho"],
        trapR=randomness["trapR"]
    )
    return note

def parseZethNote(zethNoteGRPCObj):
    noteJSON = {
        "aPK": zethNoteGRPCObj.aPK,
        "value": zethNoteGRPCObj.value,
        "rho": zethNoteGRPCObj.rho,
        "trapR": zethNoteGRPCObj.trapR
    }
    return noteJSON

def zethNoteObjFromParsed(parsedZethNote):
    note = util_pb2.ZethNote(
        aPK=parsedZethNote["aPK"],
        value=parsedZethNote["value"],
        rho=parsedZethNote["rho"],
        trapR=parsedZethNote["trapR"]
    )
    return note

def hexFmt(string):
    return "0x" + string

def initSignature():
    # TODO
    sk = getRandomAsHex()
    vk = [getRandomAsHex(), getRandomAsHex()]
    return sk, vk

def signSignature(sk, message):
    #TODO
    return 0

def verifySignature(vk, messages, signature):
    #TODO
    return 0

# Used by the recipient of a payment to recompute the commitment and check the membership in the tree
# to confirm the validity of a payment
def computeCommitment(zethNoteGRPCObj):
    m = MiMC7()

    aPK = int(zethNoteGRPCObj.aPK, 16)
    rho = int(zethNoteGRPCObj.rho, 16)
    trapR = int(zethNoteGRPCObj.trapR, 16)
    value = int(zethNoteGRPCObj.value, 16)

    cm = m.hash([aPK, rho, value], trapR, "clearmatics_cm")

    return hex(cm)[2:]

def hexadecimalDigestToBinaryString(digest):
    binary = lambda x: "".join(reversed( [i+j for i,j in zip( *[ ["{0:04b}".format(int(c,16)) for c in reversed("0"+x)][n::2] for n in [1,0]])]))
    return binary(digest)

def computeNullifier(zethNote, ask):
    m = MiMC7()

    rho = zethNote.rho 
    if type(rho) == str:
        rho = int(rho, 16)

    if type(ask) == str:
        ask = int(ask, 16)

    # nf = MiMCHash(a_sk,rho)
    nullifier = m.hash([rho], ask, "clearmatics_sn")


    return hex(nullifier)[2:]

def computeRho(i, phi, ask):
    m = MiMC7()

    if type(phi) == str:
        phi = int(phi, 16)

    if type(ask) == str:
        ask = int(ask, 16)

    # rho = MiMCHash(phi, a_sk)
    rho = m.hash([ask], phi, "clearmatics_rho_"+str(i))

    return hex(rho)[2:]

def computeHi(i, ask, hsig):
    m = MiMC7()

    if type(hsig) == str:
        hsig = int(hsig, 16)

    if type(ask) == str:
        ask = int(ask, 16)

    # rho = MiMCHash(phi, a_sk)
    rho = m.hash([hsig], ask, "clearmatics_pk_"+str(i))
    
    return hex(rho)[2:]

def computeHSig(randomSeed, old_nfs, joinSplitPubKey):
    #ZCash uses Blake2b, we'll use mimc for praticality
    m = MiMC7()

    if type(randomSeed) == str:
        randomSeed = int(randomSeed, 16)

    inputs = []
    for i in range(len(old_nfs)):
        if type(old_nfs[i]) == str:
            inputs.append(int(old_nfs[i], 16))
        elif type(old_nfs[i]) == int:
            inputs.append(old_nfs[i])
        else:
            print("computeHsig: input error")

    for i in range(len(joinSplitPubKey)):
        if type(joinSplitPubKey[i]) == str:
            inputs.append(int(joinSplitPubKey[i], 16))
        elif type(old_nfs[i]) == int:
            inputs.append(joinSplitPubKey[i])
        else:
            print("computeHsig: input error")

    h_sig = m.hash(inputs, randomSeed, "clearmatics_hsig")

    return hex(h_sig)[2:]


# TODO change name since it could be misleading by reading the code: it works well for any number, not only int64
def int64ToHexadecimal(number):
    return '{:016x}'.format(number)

def deriveAPK(ask):
    # apk = MiMCHash(a_sk, 0)
    m = MiMC7(b"clearmatics_add")

    ask = int(ask, 16)

    apk = m.hash([0], ask, "clearmatics_add")

    return hex(apk)[2:]

def generateApkAskKeypair():
    ask = bytes(Random.get_random_bytes(32)).hex()
    apk = deriveAPK(ask)
    keypair = {
        "aSK": ask,
        "aPK": apk
    }
    return keypair


def createJSInput(merklePath, address, note, ask, nullifier):
    jsInput = util_pb2.JSInput(
        merkleNode=merklePath,
        address=address,
        note=note,
        spendingASK=ask,
        nullifier=nullifier
    )
    return jsInput

def parseHexadecimalPointBaseGroup1Affine(point):
  return [point.xCoord, point.yCoord]

def parseHexadecimalPointBaseGroup2Affine(point):
  return [
    [point.xC1Coord, point.xC0Coord],
    [point.yC1Coord, point.yC0Coord]
  ]

def make_empty_message():
    return empty_pb2.Empty()

def parseVerificationKeyPGHR13(vkObj):
    vkJSON = {}
    vkJSON["a"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csPpzksnarkVerificationKey.a)
    vkJSON["b"] = parseHexadecimalPointBaseGroup1Affine(vkObj.r1csPpzksnarkVerificationKey.b)
    vkJSON["c"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csPpzksnarkVerificationKey.c)
    vkJSON["g"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csPpzksnarkVerificationKey.g)
    vkJSON["gb1"] = parseHexadecimalPointBaseGroup1Affine(vkObj.r1csPpzksnarkVerificationKey.gb1)
    vkJSON["gb2"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csPpzksnarkVerificationKey.gb2)
    vkJSON["z"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csPpzksnarkVerificationKey.z)
    vkJSON["IC"] = json.loads(vkObj.r1csPpzksnarkVerificationKey.IC)
    return vkJSON

def parseVerificationKeyGROTH16(vkObj):
    vkJSON = {}
    vkJSON["alpha_g1"] = parseHexadecimalPointBaseGroup1Affine(vkObj.r1csGgPpzksnarkVerificationKey.alpha_g1)
    vkJSON["beta_g2"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csGgPpzksnarkVerificationKey.beta_g2)
    vkJSON["gamma_g2"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csGgPpzksnarkVerificationKey.gamma_g2)
    vkJSON["delta_g2"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csGgPpzksnarkVerificationKey.delta_g2)
    vkJSON["gamma_abc_g1"] = json.loads(vkObj.r1csGgPpzksnarkVerificationKey.gamma_abc_g1)
    return vkJSON

def parseVerificationKey(vkObj, zksnark):
    if zksnark == constants.PGHR13_ZKSNARK:
        return parseVerificationKeyPGHR13(vkObj)
    elif zksnark == constants.GROTH16_ZKSNARK:
        return parseVerificationKeyGROTH16(vkObj)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)

# Writes the verification key (object) in a json file
def writeVerificationKey(vkObj, zksnark):
    vkJSON = parseVerificationKey(vkObj, zksnark)
    setupDir = os.environ['ZETH_TRUSTED_SETUP_DIR']
    filename = os.path.join(setupDir, "vk.json")
    with open(filename, 'w') as outfile:
        json.dump(vkJSON, outfile)

def makeProofInputs(root, jsInputs, jsOutputs, inPubValue, outPubValue, hsig, his, phi):
    return prover_pb2.ProofInputs(
        root=root,
        jsInputs=jsInputs,
        jsOutputs=jsOutputs,
        inPubValue=inPubValue,
        outPubValue=outPubValue,
        hSig=hsig,
        hi=his,
        phi=phi
    )

def parseProofPGHR13(proofObj):
    proofJSON = {}
    proofJSON["a"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.a)
    proofJSON["a_p"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.aP)
    proofJSON["b"] = parseHexadecimalPointBaseGroup2Affine(proofObj.r1csPpzksnarkExtendedProof.b)
    proofJSON["b_p"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.bP)
    proofJSON["c"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.c)
    proofJSON["c_p"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.cP)
    proofJSON["h"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.h)
    proofJSON["k"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.k)
    proofJSON["inputs"] = json.loads(proofObj.r1csPpzksnarkExtendedProof.inputs)
    return proofJSON

def parseProofGROTH16(proofObj):
    proofJSON = {}
    proofJSON["a"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csGgPpzksnarkExtendedProof.a)
    proofJSON["b"] = parseHexadecimalPointBaseGroup2Affine(proofObj.r1csGgPpzksnarkExtendedProof.b)
    proofJSON["c"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csGgPpzksnarkExtendedProof.c)
    proofJSON["inputs"] = json.loads(proofObj.r1csGgPpzksnarkExtendedProof.inputs)
    return proofJSON

def parseProof(proofObj, zksnark):
    if zksnark == constants.PGHR13_ZKSNARK:
        return parseProofPGHR13(proofObj)
    elif zksnark == constants.GROTH16_ZKSNARK:
        return parseProofGROTH16(proofObj)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)

def get_proof_joinsplit_2by2(
        grpcEndpoint,
        mk_root,
        input_note1,
        input_address1,
        mk_path1,
        sender_ask1,
        input_note2,
        input_address2,
        mk_path2,
        sender_ask2,
        recipient1_apk,
        recipient2_apk,
        output_note_value1,
        output_note_value2,
        public_in_value,
        public_out_value,
        zksnark
    ):
    input_nullifier1 = computeNullifier(input_note1, sender_ask1)
    input_nullifier2 = computeNullifier(input_note2, sender_ask2)
    js_inputs = [
        createJSInput(mk_path1, input_address1, input_note1, sender_ask1, input_nullifier1),
        createJSInput(mk_path2, input_address2, input_note2, sender_ask2, input_nullifier2)
    ]

    sk, vk = initSignature()
    
    phi = getRandomAsHex()
    randomSeed = getRandomAsHex()
    hsig = computeHSig(randomSeed, [input_nullifier1, input_nullifier2], vk)

    h_0 = computeHi(0, sender_ask1, hsig)    
    h_1 = computeHi(1, sender_ask2, hsig)
    his = [
        h_0,
        h_1
    ]    

    signature = signSignature(sk, []) # TODO

    output_note1 = createZethNote(noteRandomness(0, phi, hsig), recipient1_apk, output_note_value1)
    output_note2 = createZethNote(noteRandomness(1, phi, hsig), recipient2_apk, output_note_value2)
    js_outputs = [
        output_note1,
        output_note2
    ]

    proof_input = makeProofInputs(mk_root, js_inputs, js_outputs, public_in_value, public_out_value, hsig, his, phi)

    proof_obj = getProof(grpcEndpoint, proof_input)

    proof_json = parseProof(proof_obj, zksnark)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (output_note1, output_note2, proof_json) #TODO return signature
