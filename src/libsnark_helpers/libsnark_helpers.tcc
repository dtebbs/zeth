#ifndef __ZETH_LIBSNARK_HELPERS_TCC__
#define __ZETH_LIBSNARK_HELPERS_TCC__

namespace libzeth {

// SerializableT represents any type that overloads the operator<< and operator>> of ostream and istream
// Note: Both r1cs_ppzksnark_proving_key and r1cs_ppzksnark_verifying_key implement
// these overloading, so both of them can easily be writen and loaded from files
template<typename serializableT>
void writeToFile(boost::filesystem::path path, serializableT& obj) {
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    ss << obj;

    // ofstream: Stream class to write on files
    std::ofstream fh;

    fh.open(str_path, std::ios::binary); // We open our ofstream in binary mode
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

template<typename serializableT>
serializableT loadFromFile(boost::filesystem::path path) {
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;

    // ifstream: Stream class to read from files (opened in binary mode)
    std::ifstream fh(str_path, std::ios::binary);
    assert(fh.is_open());

    // Get a stream buffer from the ifstream and "dump" its content to the stringstream
    ss << fh.rdbuf();
    fh.close();

    // Set internal position pointer to absolute position 0
    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    serializableT obj;
    ss >> obj;

    return obj;
};

template<typename ppT>
void serializeProvingKeyToFile(provingKeyT<ppT> &pk, boost::filesystem::path pk_path)
{
    writeToFile<provingKeyT<ppT>>(pk_path, pk);
};

template<typename ppT>
provingKeyT<ppT> deserializeProvingKeyFromFile(boost::filesystem::path pk_path)
{
    return loadFromFile<provingKeyT<ppT>>(pk_path);
};

template<typename ppT>
void serializeVerificationKeyToFile(verificationKeyT<ppT> &vk, boost::filesystem::path vk_path)
{
    writeToFile<verificationKeyT<ppT>>(vk_path, vk);
};

template<typename ppT>
verificationKeyT<ppT> deserializeVerificationKeyFromFile(boost::filesystem::path vk_path)
{
    return loadFromFile<verificationKeyT<ppT>>(vk_path);
};

template<typename ppT>
void writeSetup(keyPairT<ppT> keypair, boost::filesystem::path setup_dir)
{
	if (setup_dir.empty())
    {
        setup_dir = getPathToSetupDir();
	}

	boost::filesystem::path vk_json("vk.json");
	boost::filesystem::path vk_raw("vk.raw");
	boost::filesystem::path pk_raw("pk.raw");

	boost::filesystem::path path_vk_json = setup_dir / vk_json;
	boost::filesystem::path path_vk_raw = setup_dir / vk_raw;
	boost::filesystem::path path_pk_raw = setup_dir / pk_raw;

    provingKeyT<ppT> proving_key = keypair.pk;
    verificationKeyT<ppT> verification_key = keypair.vk;

	verificationKeyToJson<ppT>(verification_key, path_vk_json);

	serializeVerificationKeyToFile<ppT>(verification_key, path_vk_raw);
	serializeProvingKeyToFile<ppT>(proving_key, path_pk_raw);
};

template<typename ppT>
void r1csConstraintsToJson(libsnark::linear_combination<libff::Fr<ppT> > constraints, boost::filesystem::path path)
{
	if (path.empty())
    {
		boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
		boost::filesystem::path constraints_json("constraints.json");
		path = tmp_path / constraints_json;
	}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    fillJsonConstraintsInSs(constraints, ss);

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

template<typename ppT>
void fillJsonConstraintsInSs(libsnark::linear_combination<libff::Fr<ppT> > constraints, std::stringstream& ss)
{
    ss << "{";
    uint count = 0;
    for (const libsnark::linear_term<libff::Fr<ppT> >& lt : constraints.terms) {
        if (count != 0) {
            ss << ",";
        }

        if (lt.coeff != 0 && lt.coeff != 1) {
            ss << '"' << lt.index << '"' << ":" << "-1";
        } else {
            ss << '"' << lt.index << '"' << ":" << lt.coeff;
        }
        count++;
    }
    ss << "}";
};

template <typename ppT>
void arrayToJson(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path) {
	if (path.empty())
    {
		boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
		boost::filesystem::path array_json("array.json");
		path = tmp_path / array_json;
	}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    libsnark::r1cs_variable_assignment<libff::Fr<ppT> > values = pb.full_variable_assignment();
    ss << "\n{\"TestVariables\":[";

    for (size_t i = 0; i < values.size(); ++i) {
        ss << values[i].as_bigint();
        if (i <  values.size() - 1) { ss << ",";}
    }

    ss << "]}\n";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

template<typename ppT>
void r1csToJson(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path) {
	if (path.empty()) {
		boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
		boost::filesystem::path r1cs_json("r1cs.json");
		path = tmp_path / r1cs_json;
	}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    // output inputs, right now need to compile with debug flag so that the `variable_annotations`
    // exists. Having trouble setting that up so will leave for now.
    libsnark::r1cs_constraint_system<ppT> constraints = pb.get_constraint_system();
    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "\n{\"variables\":[";

    for (size_t i = 0; i < input_variables + 1; ++i) {
        ss << '"' << constraints.variable_annotations[i].c_str() << '"';
        if (i < input_variables ) {
            ss << ", ";
        }
    }
    ss << "],\n";
    ss << "\"constraints\":[";

    for (size_t c = 0; c < constraints.num_constraints(); ++c) {
        ss << "[";// << "\"A\"=";
        fillJsonConstraintsInSs<ppT>(constraints.constraints[c].a, ss);
        ss << ",";// << "\"B\"=";
        fillJsonConstraintsInSs<ppT>(constraints.constraints[c].b, ss);
        ss << ",";// << "\"A\"=";;
        fillJsonConstraintsInSs<ppT>(constraints.constraints[c].c, ss);
        if (c == constraints.num_constraints()-1 ) {
            ss << "]\n";
        } else {
            ss << "],\n";
        }
    }
    ss << "]}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

template<typename ppT>
void primary_input_to_json(libsnark::r1cs_ppzksnark_primary_input<ppT> input, boost::filesystem::path path) {
	if (path.empty()) {
		boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
		boost::filesystem::path primary_input_json("primary_input.json");
		path = tmp_path / primary_input_json;
	}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{\n";
    ss << " \"inputs\" :" << "["; // 1 should always be the first variable passed
    for (size_t i = 0; i < input.size(); ++i) {
        ss << "\"0x" << HexStringFromLibsnarkBigint(input[i].as_bigint()) << "\"";
        if ( i < input.size() - 1 ) {
            ss<< ", ";
        }
    }
    ss << "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

} // libzeth

#endif // __ZETH_LIBSNARK_HELPERS_TCC__
