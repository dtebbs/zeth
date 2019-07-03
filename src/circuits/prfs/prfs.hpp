#ifndef __ZETH_PRFS_CIRCUITS_HPP__
#define __ZETH_PRFS_CIRCUITS_HPP__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/prfs.tcc

#include <libsnark/gadgetlib1/gadget.hpp>
#include "circuits/circuits-util.hpp"
#include "circuits/mimc/mimc_hash.hpp"

namespace libzeth {

// a_pk = mimc_hash_(iv_pk)(a_sk, 0)
// Adapted from previous: a_pk = sha256(a_sk || 0^256): See Zerocash extended paper, page 22,
// paragraph "Instantiating the NP statement POUR"

template<typename FieldT>
class PRF_addr_a_pk_gadget : public MiMC_hash_gadget<FieldT> {
public:
    PRF_addr_a_pk_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable<FieldT>& a_sk,
                        const std::string &annotation_prefix = " a_pk_PRF_gadget");

};

// PRF to generate the nullifier
// nf = sha256(a_sk || 01 || [rho]_254): See Zerocash extended paper, page 22
// nf = mimc_hash_(iv_nf)(a_sk, rho)

template<typename FieldT>
class PRF_nf_gadget : public MiMC_hash_gadget<FieldT> {
public:
    PRF_nf_gadget(libsnark::protoboard<FieldT>& pb,
                libsnark::pb_variable<FieldT>& a_sk,
                libsnark::pb_variable<FieldT>& rho,
                const std::string &annotation_prefix = " nf_PRF_gadget");
};

// PRF to generate the nullifier
// h_i = sha256(0{i-1}00 || a_sk[:252] || h_sig): See ZCash extended paper, page 57
// h_i = mimc_hash_(iv_pk)(a_sk, i, h_sig)

template<typename FieldT>
class PRF_pk_gadget : public MiMC_hash_gadget<FieldT> {
public:
    PRF_pk_gadget(libsnark::protoboard<FieldT>& pb,
                libsnark::pb_variable<FieldT>& a_sk,
                libsnark::pb_variable<FieldT>& i,
                libsnark::pb_variable<FieldT>& h_sig,
                const std::string &annotation_prefix = " pk_PRF_gadget");
};

// PRF to generate the nullifier
// rho_i = sha256(0{i-1}10 || phi[:252] || h_sig): See ZCash extended paper, page 57
// rho_i = mimc_hash_(iv_rho)(phi, i, h_sig)

template<typename FieldT>
class PRF_rho_gadget : public MiMC_hash_gadget<FieldT> {
public:
    PRF_rho_gadget(libsnark::protoboard<FieldT>& pb,
                libsnark::pb_variable<FieldT>& phi,
                libsnark::pb_variable<FieldT>& i,
                libsnark::pb_variable<FieldT>& h_sig,
                const std::string &annotation_prefix = " rho_PRF_gadget");
};

} // libzeth
#include "circuits/prfs/prfs.tcc"

#endif // __ZETH_PRFS_CIRCUITS_HPP__
