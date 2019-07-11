#ifndef __ZETH_JOINSPLIT_CIRCUIT_TCC__
#define __ZETH_JOINSPLIT_CIRCUIT_TCC__

//#include <libsnark/common/data_structures/merkle_tree.hpp>
//#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
//#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
//#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include <src/types/merkle_tree.hpp>
#include <src/circuits/merkle_tree/merkle_path_authenticator.hpp>

#include <boost/static_assert.hpp>

#include "libsnark_helpers/libsnark_helpers.hpp"

//#include "circuits/sha256/sha256_ethereum.hpp"
#include "circuits/mimc/mimc_hash.hpp"

#include "circuits/notes/note.hpp" // Contains the circuits for the notes

#include "circuits/prfs/prfs.hpp" // Contains the circuits for the PRFs

#include "types/joinsplit.hpp"

#include "zeth.h" // Contains the definitions of the constants we use

using namespace libsnark;
using namespace libff;
using namespace libzeth;

template<typename FieldT, typename HashT, size_t NumInputs, size_t NumOutputs>
class joinsplit_gadget : libsnark::gadget<FieldT> {
    private:
        // ---- Primary inputs (public) ---- //
        std::shared_ptr<pb_variable<FieldT> > merkle_root;                                  // Merkle root
        std::array<std::shared_ptr<pb_variable<FieldT> >, NumInputs> input_nullifiers;      // List of nullifiers of the notes to spend
        std::array<std::shared_ptr<pb_variable<FieldT> >, NumOutputs> output_commitments;   // List of commitments generated for the new notes
        std::array<std::shared_ptr<pb_variable<FieldT> >, NumInputs> a_sks;
        pb_variable<FieldT> h_sig;
        std::array<std::shared_ptr<pb_variable<FieldT> >, NumInputs> h_is;
        pb_variable<FieldT> phi;
        std::array<std::shared_ptr<pb_variable<FieldT> >, NumOutputs> rho_is;
        pb_variable<FieldT> zk_vpub_in;                                                     // Public value that is put into the mix
        pb_variable<FieldT> zk_vpub_out;                                                    // Value that is taken out of the mix

        // ---- Auxiliary inputs (private) ---- //
        //pb_variable<FieldT> zk_total;                                                       // Total amount transfered in the transaction ; needed if we want to constraint the total amount transfered
        std::array<std::shared_ptr<input_note_gadget<HashT, FieldT>>, NumInputs> input_notes; // Input note gadgets
        std::array<std::shared_ptr<output_note_gadget<FieldT>>, NumOutputs> output_notes;     // Output note gadgets
        std::array<std::shared_ptr<PRF_pk_gadget<FieldT>>, NumInputs> h_i_gadgets;
        std::array<std::shared_ptr<PRF_rho_gadget<FieldT>>, NumOutputs> rho_i_gadgets;

    public:
        // Make sure that we do not exceed the number of inputs/outputs
        // specified in zeth's configuration file (see: zeth.h file)
        BOOST_STATIC_ASSERT(NumInputs <= ZETH_NUM_JS_INPUTS);
        BOOST_STATIC_ASSERT(NumOutputs <= ZETH_NUM_JS_OUTPUTS);

        // Primary inputs are packed to be added to the extended proof and given to the verifier on-chain
        joinsplit_gadget(protoboard<FieldT> &pb,
                        const std::string &annotation_prefix = "joinsplit_gadget"
        ) : gadget<FieldT>(pb) {

            //A JoinSplit proof primary inputs consists of (
            // rt, nf old, cm_new, v_pub_in, v_pub_out
            // h_sig, h_i_old
            //)
            int nb_inputs = 1 + NumInputs + NumOutputs + 1 + 1 + 1 + NumInputs;
            pb.set_input_sizes(nb_inputs);

            // A Join Split description _however_ consists of 
            // {v_pib_in, v_pib_out, rt, <nf_old<, <cm_new>, epk, randomSeed, <h_i_old>, pi_zk, <cipher>}

            // Block dedicated to generate the verifier inputs
            {

                // Initialize the variables
                merkle_root.reset(new libsnark::pb_variable<FieldT>);
                (*merkle_root).allocate(pb, FMT(this->annotation_prefix, " merkle_root"));

                for (size_t i = 0; i < NumInputs; i++) {
                    input_nullifiers[i].reset(new libsnark::pb_variable<FieldT>);
                    (*input_nullifiers[i]).allocate(pb, FMT(this->annotation_prefix, " input_nullifiers_%zu", i));
                }

                for (size_t i = 0; i < NumOutputs; i++) {
                    output_commitments[i].reset(new libsnark::pb_variable<FieldT>);
                    (*output_commitments[i]).allocate(pb, FMT(this->annotation_prefix, " output_commitments_%zu", i));
                }

                // Allocate the zk_vpub_in
                zk_vpub_in.allocate(pb, FMT(this->annotation_prefix, " public value in"));

                // Allocate the zk_vpub_out
                zk_vpub_out.allocate(pb, FMT(this->annotation_prefix, " public value out"));

                h_sig.allocate(pb, FMT(this->annotation_prefix, " transaction hash h_sig"));

                for (size_t i = 0; i < NumInputs; i++) {
                    h_is[i].reset(new libsnark::pb_variable<FieldT>);
                    (*h_is[i]).allocate(pb, FMT(this->annotation_prefix, " non malleability h_%zu", i));
                }

            } // End of the block dedicated to generate the verifier inputs

            for (size_t i = 0; i < NumInputs; i++) {
                a_sks[i].reset(new libsnark::pb_variable<FieldT>);
                (*a_sks[i]).allocate(pb, FMT(this->annotation_prefix, " a_sk_%zu", i));
            }

            phi.allocate(pb, FMT(this->annotation_prefix, " nullifier randomness phi"));

            for (size_t i = 0; i < NumOutputs; i++) {
                rho_is[i].reset(new libsnark::pb_variable<FieldT>);
                (*rho_is[i]).allocate(pb, FMT(this->annotation_prefix, " nullifier randomness rho_%zu", i));
            }

            //zk_total.allocate(pb, "zk total");

            // Gadget verifying the h_i have been well computed
            // We keep these gadgets outside of the note to reuse the h_sig pb_variable as well as the a_sk
            for (size_t i = 0; i < NumInputs; i++)
            {
                pb_variable<FieldT> i_pb = get_var(pb, FieldT(i), FMT(this->annotation_prefix, "i_%zu", i));
                h_i_gadgets[i].reset( new PRF_pk_gadget<FieldT>(
                    pb,
                    *a_sks[i],
                    i_pb,
                    h_sig,
                    FMT(this->annotation_prefix, " h_i_gadget_%zu", i)
                ));
            }
            
            // Gadget verifying the rho_i have been well computed
            // We keep these gadgets outside of the note to reuse the h_sig pb_variable as well as the phi
            for (size_t i = 0; i < NumOutputs; i++)
            {
                pb_variable<FieldT> i_pb = get_var(pb, FieldT(i), FMT(this->annotation_prefix, "i_%zu", i));
                rho_i_gadgets[i].reset( new PRF_rho_gadget<FieldT>(
                    pb,
                    phi,
                    i_pb,
                    h_sig,
                    FMT(this->annotation_prefix, " rho_i_gadget_%zu", i)
                ));
            }

            // Input note gadgets for commitments, nullifiers, and spend authority
            for (size_t i = 0; i < NumInputs; i++) {
                input_notes[i].reset(new input_note_gadget<HashT, FieldT>(
                    pb,
                    input_nullifiers[i],
                    *merkle_root,
                    a_sks[i],
                    FMT(this->annotation_prefix, " input_note_gadget_%zu", i)
                ));
            }


            for (size_t i = 0; i < NumOutputs; i++) {
                output_notes[i].reset(new output_note_gadget<FieldT>(
                    pb,
                    output_commitments[i],
                    rho_is[i],
                    FMT(this->annotation_prefix, " output_note_gadget_%zu", i)
                ));
            }
        }

        void generate_r1cs_constraints() {
            //merkle_root->generate_r1cs_constraints();Z

            // Constrain the h_i
            for (size_t i = 0; i < NumInputs; i++) {
                h_i_gadgets[i]->generate_r1cs_constraints();
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                        1,
                        *h_is[i],
                        h_i_gadgets[i]->result()
                    ),
                    FMT(this->annotation_prefix, " h_i_equality_constraint")
                );
            }

            // Constrain the rho_i
            for (size_t i = 0; i < NumInputs; i++) {
                rho_i_gadgets[i]->generate_r1cs_constraints();
            }

            // Constrain the JoinSplit inputs
            for (size_t i = 0; i < NumInputs; i++) {
                input_notes[i]->generate_r1cs_constraints();
            }

            // Constrain the JoinSplit outputs
            for (size_t i = 0; i < NumOutputs; i++) {
                output_notes[i]->generate_r1cs_constraints();
            }


            // Generate the constraints to ensure that the condition of the joinsplit holds (ie: LHS = RHS)

            {
                // Compute the LHS
                linear_combination<FieldT>* left_side = new linear_combination<FieldT>(linear_term<FieldT>(zk_vpub_in));
                for (size_t i = 0; i < NumInputs; i++) {
                    (*left_side).add_term(linear_term<FieldT>(input_notes[i]->value));
                }

                // Compute the RHS
                linear_combination<FieldT>* right_side = new linear_combination<FieldT>(linear_term<FieldT>(zk_vpub_out));
                for (size_t i = 0; i < NumOutputs; i++) {
                    (*right_side).add_term(linear_term<FieldT>(output_notes[i]->value));
                }

                // Ensure that both sides are equal (ie: 1 * left_side = right_side)
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                        1,
                        *left_side,
                        *right_side
                    ),
                    FMT(this->annotation_prefix, " lhs_rhs_equality_constraint")
                );

                // See: https://github.com/zcash/zcash/issues/854
                // Update add constraint on ouput values (<= v_max) for consistency with the paper

                // Constraint total amount transfered (not needed so far)
                // We need a new variable (zk_total) as left/right_side are linear combinations
                /*
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                        1,
                        left_side,
                        packed_addition(zk_total_uint64)
                    ),
                    FMT(this->annotation_prefix, " lhs_equal_zk_total_constraint")

                );
                */
            }

        }

        void generate_r1cs_witness(
            const FieldT& rt,
            const std::array<JSInput<FieldT>, NumInputs>& inputs,
            const std::array<ZethNote<FieldT>, NumOutputs>& outputs,
            FieldT vpub_in,
            FieldT vpub_out,
            FieldT h_sig_in,
            FieldT phi_in,
            std::array<FieldT, NumInputs> h_i
        ) {
            // Witness the merkle root
            this->pb.val(*merkle_root) = rt ;

            //// Witness public values

            // Witness LHS public value
            this->pb.val(zk_vpub_in) = vpub_in;

            // Witness RHS public value
            this->pb.val(zk_vpub_out) = vpub_out;

            this->pb.val(h_sig) = h_sig_in;

            this->pb.val(phi) = phi_in;

            // Compute zk_total out of left_side
            /*
            {
                // Witness total_uint64 bits
                // We add binary numbers here
                // see: https://stackoverflow.com/questions/13282825/adding-binary-numbers-in-c
                bits64 left_side_acc = vpub_in;
                for (size_t i = 0; i < NumInputs; i++) {
                    left_side_acc = binaryAddition<64>(left_side_acc, inputs[i].note.value());
                }

                zk_total_uint64.fill_with_bits(
                    this->pb,
                    get_vector_from_bits64(left_side_acc)
                );
            }
            */

            // Witness the JoinSplit inputs
            for (size_t i = 0; i < NumInputs; i++) {
                std::vector<FieldT> merkle_path = inputs[i].witness_merkle_path;
                size_t address = inputs[i].address;
                libff::bit_vector address_bits = get_vector_from_bitsAddr(inputs[i].address_bits);

                this->pb.val(*a_sks[i]) = inputs[i].spending_key_a_sk;

                h_i_gadgets[i]->generate_r1cs_witness();

                this->pb.val(*h_is[i]) = h_i[i];

                input_notes[i]->generate_r1cs_witness(
                    merkle_path,
                    address_bits,
                    inputs[i].note
                );

            }

            // Witness the JoinSplit outputs
            for (size_t i = 0; i < NumOutputs; i++) {
                rho_i_gadgets[i]->generate_r1cs_witness();

                this->pb.val(*rho_is[i]) = this->pb.val( rho_i_gadgets[i]->result() );

                output_notes[i]->generate_r1cs_witness(outputs[i]);
            }

            // [SANITY CHECK] Ensure that the intended root
            // was witnessed by the inputs, even if the read
            // gadget overwrote it. This allows the prover to
            // fail instead of the verifier, in the event that
            // the roots of the inputs do not match the
            // treestate provided to the proving API.
            /*
            merkle_root->bits.fill_with_bits(
                this->pb,
                get_vector_from_bits256(rt)
            );
            */
            //TODO Not sure whether the previous line is needed anylonger, we should not overwrite the root now

            bool is_valid_witness = this->pb.is_satisfied();
            std::cout << "************* SAT result: " << is_valid_witness <<  " ******************" << std::endl;

        }

        // Computes the binary size of the primary inputs
        static size_t get_input_bit_size() {
            size_t acc = 0;

            // the Merkle Root (anchor)
            acc += 1;

            // the NullifierS
            for (size_t i = 0; i < NumInputs; i++) {
                acc += 1;
            }

            // the CommitmentS
            for (size_t i = 0; i < NumOutputs; i++) {
                acc += 1;
            }

            // the public value in
            acc += 1;

            // the public value out
            acc += 1;

            // h_sig
            acc += 1;

            // h_1..N^old
            for (size_t i = 0; i < NumOutputs; i++) {
                acc += 1;
            }
            
            return acc;
        }

        // Computes the number of field elements in the primary inputs
        static size_t verifying_field_element_size() {
            return get_input_bit_size();
        }

};

#endif // __ZETH_JOINSPLIT_CIRCUIT_TCC__
