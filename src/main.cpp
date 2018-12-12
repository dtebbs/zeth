#include <iostream>

#include <libsnark_helpers/libsnark_helpers.hpp>
#include <prover/prover.hpp>
#include <prover/computation.hpp>
#include <sha256/sha256_ethereum.hpp>

#include <cli/mainCmd.hpp>
#include <cli/setupCmd.hpp>
#include <cli/proveCmd.hpp>

int main(int argc, char* argv[]) {
    // The first argument is the executable itself, and the second is the command
    // The executable itself does nothing, we need to specify a command
    std::string program(argv[0]);
    if (argc < 2) {
        printUsage(program);
        return 1;
    }

    // Two commands supported
    // One to compute the trusted setup, the other one to compute proofs (verification happens on chain)
    std::string command(argv[1]);
    if (command != "setup" && command != "prove") {
        std::cerr << "Unknown command" << std::endl;
        printUsage(program);
        return 1;
    }
    
    // See: https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/alt_bn128/alt_bn128_init.cpp
    libff::alt_bn128_pp::init_public_params();
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;

    // Instantiate the prover
    // The hash function we use everywhere here is sha256 as defined in the ethereum code base
    // This is the function used for: the commitments and also to compute the merkle tree (the inner nodes of the tree)
    //
    // ** WARNING: Security note **
    // Because our commitment scheme is based on sha256, our scheme is secure only in the Random Oracle model
    // See the comment https://github.com/zcash/zcash/issues/2234#issuecomment-292419085
    // for more details on the security analysis of the switch from sha256 to Pedersen commitments in Zcash
    Miximus<FieldT, sha256_ethereum> prover;

    int error = 0;
    switch (getCommandCode(command)) {
        case SETUP: error = setupCommand(prover); break;
        case PROVE: error = proveCommand(argc, argv); break;
        default: unknownCommand(program); return 1;
    }

    if (error) {
        std::cerr << "[ERROR] Something went wrong while executing the command" << std::endl;
        return 1;
    }

    return 0;
}
