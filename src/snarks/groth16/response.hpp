#ifndef __ZETH_RESPONSE_HPP__
#define __ZETH_RESPONSE_HPP__

#include "libsnark_helpers/extended_proof.hpp"

#include "prover.grpc.pb.h"
#include "util_api.hpp"

using proverpkg::VerificationKey;
using proverpkg::ExtendedProof;
using proverpkg::R1csGgPpzksnarkExtendedProof;
using proverpkg::R1csGgPpzksnarkVerificationKey;
using proverpkg::HexadecimalPointBaseGroup1Affine;
using proverpkg::HexadecimalPointBaseGroup2Affine;

namespace libzeth {

template<typename ppT> void PrepareProofResponse(extended_proof<ppT>& ext_proof, ExtendedProof* message);
template<typename ppT>void PrepareVerifyingKeyResponse(libsnark::r1cs_gg_ppzksnark_verification_key<ppT>& vk, VerificationKey* message);

} // libzeth
#include "snarks/groth16/response.tcc"

#endif // __ZETH_RESPONSE_HPP__
