#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>

// Get the gadget to test
#include "circuits/commitments/commitments.hpp"

using namespace libzeth;
using namespace libsnark;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt

namespace {

TEST(TestCOMMs, TestCMGadget) {
  ppT::init_public_params();
  protoboard<FieldT> pb;


  libsnark::pb_variable<FieldT> a_pk;
  libsnark::pb_variable<FieldT> rho;
  libsnark::pb_variable<FieldT> r;
  libsnark::pb_variable<FieldT> v;

  a_pk.allocate(pb, "a_pk");
  pb.val(a_pk) = FieldT("5387907419355715653531038695566357046482139005118304712469340438697294642611");

  rho.allocate(pb, "rho");
  pb.val(rho) = FieldT("12946791413528024759839394340318236878559158148001437182189040772047964059643");

  r.allocate(pb, "r trap");
  pb.val(r) = FieldT("6576838732374919021860119342200398901974877797242970520445052250557344565821");

  v.allocate(pb, "v");
  pb.val(v) = FieldT("100");

  cm_gadget<FieldT> cm_gadget(pb, a_pk, rho, r,  v, "cm_test_gadget");

  cm_gadget.generate_r1cs_constraints();
  cm_gadget.generate_r1cs_witness();

  FieldT expected_out = FieldT("7696443061196341087326334761452156208417519921123230974759309762690342959594");

  ASSERT_TRUE(expected_out == pb.val(cm_gadget.result()));
};


} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
