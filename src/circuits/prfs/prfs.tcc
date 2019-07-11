#ifndef __ZETH_PRFS_CIRCUITS_TCC__
#define __ZETH_PRFS_CIRCUITS_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/prfs.tcc

namespace libzeth {

//TODO add PRF parent class

// a_pk = sha256(1100 || a_sk[:252] || 0^256): See ZCash extended paper, page 57
// Generating public address addr from secret key a_sk
template<typename FieldT>
PRF_addr_a_pk_gadget<FieldT>::PRF_addr_a_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& a_sk,
        const std::string &annotation_prefix
      ) :
      MiMC_hash_gadget<FieldT>(pb, {get_var(pb, FieldT("0"), "zero_var")}, a_sk, get_iv_add(), annotation_prefix)
{
  //
}

// PRF to generate the nullifier
// nf = sha256(1110 || a_sk[:252] || rho): See ZCash extended paper, page 57
template<typename FieldT>
PRF_nf_gadget<FieldT>::PRF_nf_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& a_sk,
        libsnark::pb_variable<FieldT>& rho,
        const std::string &annotation_prefix) :
      MiMC_hash_gadget<FieldT>(pb, {rho}, a_sk, get_iv_sn(), annotation_prefix)
{
  //
}

// PRF to generate the nullifier
// h_i = sha256(0{i-1}00 || a_sk[:252] || h_sig): See ZCash extended paper, page 57
template<typename FieldT>
PRF_pk_gadget<FieldT>::PRF_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& a_sk,
        libsnark::pb_variable<FieldT>& i,
        libsnark::pb_variable<FieldT>& h_sig,
        const std::string &annotation_prefix) :
      MiMC_hash_gadget<FieldT>(pb, {h_sig}, a_sk, get_iv_pk(pb.val(i)), annotation_prefix)
{
  //
}

// PRF to generate the nullifier
// rho_i = sha256(0{i-1}10 || phi[:252] || h_sig): See ZCash extended paper, page 57
template<typename FieldT>
PRF_rho_gadget<FieldT>::PRF_rho_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& phi,
        libsnark::pb_variable<FieldT>& i,
        libsnark::pb_variable<FieldT>& h_sig,
        const std::string &annotation_prefix) :
      MiMC_hash_gadget<FieldT>(pb, {h_sig}, phi, get_iv_rho(pb.val(i)), annotation_prefix)
{
  //
}


} //libzeth

#endif // __ZETH_PRFS_CIRCUITS_TCC__
