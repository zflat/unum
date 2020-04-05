#include <cassert>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdlib>

#include "botan_all.h"

// Notes
// https://wiki.mozilla.org/Identity/AttachedServices/KeyServerProtocol

int main() {
  std::unique_ptr<Botan::HashFunction> hash_fn(Botan::HashFunction::create_or_throw("SHA-256"));
  Botan::DL_Group group("modp/srp/2048");
  const size_t p_bytes = group.get_p().bytes();

  //Botan::BigInt a_int("0x86160");
  Botan::BigInt a_int("0x61");
  hash_fn->update(Botan::BigInt::encode_1363(a_int, p_bytes));  // gets padding applied
  //hash_fn->update(Botan::BigInt::encode_1363(a_int, 1)); // no padding applied
  Botan::secure_vector<uint8_t> a_int_h = hash_fn->final();
  Botan::BigInt a_int_val = Botan::BigInt::decode(a_int_h);

  // make a new Uint8Array with the correct padding in order
  // to match the bytes that are encoded by BigInt value

  hash_fn->update('a');
  Botan::secure_vector<uint8_t> a_char_h = hash_fn->final();
  Botan::BigInt a_char_val = Botan::BigInt::decode(a_char_h);

  hash_fn->update("61");
  Botan::secure_vector<uint8_t> a_str_h = hash_fn->final();
  Botan::BigInt a_str_val = Botan::BigInt::decode(a_str_h);

  // Note srp6_group_identifier derived from g and N. k = H(N, g)
  std::string g_id("modp/srp/2048"); // Botan::srp6_group_identifier(paramN, g);

  Botan::System_RNG rng;
  Botan:: BigInt v;
  std::string user = "person123";
  std::string pass = "pass123";
  std::string str_salt = "97E940AEF61ADB119E18BA14A92EA342FD8F79A89666E5E40FF144CFBEAC52A3";

  // v = Botan::generate_srp6_validator(user, pass);
  Botan::BigInt salt(std::string("0x").append(str_salt)); // for I=person123
  // std::cout << "size 10 " << salt.encoded_size(Botan::BigInt::Decimal) << std::endl;
  // std::cout << "size 16 " << salt.encoded_size(Botan::BigInt::Hexadecimal) << std::endl;
  // std::cout << "size 256 " << salt.encoded_size(Botan::BigInt::Binary) << std::endl;
  std::vector<uint8_t> saltV = Botan::BigInt::encode(salt, Botan::BigInt::Binary);
  Botan::BigInt salt1 = Botan::BigInt::decode(saltV);
  std::ostringstream salt_decode;
  salt_decode << std::hex << salt1;

  assert( salt_decode.str() == str_salt );
  std::cout << "salt decode " << std::hex << salt1 << std::endl;


  Botan::BigInt verifier("0x374b373f0bf527652b3be36c11bf15a3a996817fc054c143c35af8022f2dad557a99e2ed32683dd4239263d2ec3f6dac45d617446a1879173303bb0b7138be028897d73096250c9844a5d7c7f5bd3e140d2c4d3c041b11a6586c557d2f6d8110a4cde7d88f8736df937fc26a02adb372aef60a53335e99a8fe38ed0390a0388a4322de7b86b80f5ac6ff6110052e4299f6cb0117a0e5adff37871c09c704a9d235ab406663efeca219fed8efd9e3572174d7eccb702457e58a6b6be7c7a143e848ee3f42b909d5445d7537561b8d7949f80d347ad310b9cb014613bc2715c119fbefe274bfbe7d48795a4192e50b783ee519f8b94de0ee216813ffe7bff94637"); // // for I=person123, should enforce uniqueness....
  Botan::BigInt ver = Botan::generate_srp6_verifier(user, pass, saltV, g_id, "SHA-256");

  std::ostringstream ver_oss;
  ver_oss << std::hex << ver;

  std::ostringstream verifier_oss;
  verifier_oss << std::hex << verifier;

  assert( ver_oss.str() == verifier_oss.str() );
  assert( ver.cmp(verifier, true) == 0 );

  assert( Botan::same_mem(ver.data(), verifier.data(), saltV.size()) == 1);

  Botan::SRP6_Server_Session session;

  // server generates B and b, sends B to client and b to a cache

  Botan::BigInt paramB = session.step1(verifier, g_id, "SHA-256", rng);

  std::cout << "B: " << std::dec << paramB << std::endl;
  std::cout << "B_16: " << std::hex << paramB << std::endl;

  std::pair<Botan::BigInt, Botan::SymmetricKey> agree = srp6_client_agree(user, pass, g_id, "SHA-256", saltV, paramB, rng);
  std::cout << "client A:" << std::hex << agree.first << std::endl;

  // Read A from the client
  // std::getline(std::cin, strA);
  std::string strA("0x6fff5d7cfc88870fa252cd1a002db3c5500804a960bc67c0b5f3bc7100a802ab9d6ca5dec657ceb645f1f38e89d31b46f731e59204cdc74ffa0dc12049ceb09bf72ba85500e42ec12cee4ada5b0f6d240c167ee9f70f7b02a2d658e75d0bc4e310c157fba0859622c263fdb5cfe687d2be3d0b15b98d488a4c30fca3f43c9215418d6fec612610556d7c4e5e72a34da44926147e0ba9d591cdc90fe799069f6e74dc811982a18ce24eec379a9513dd524698b56c56cd1997aa2f100db7d3985fc8dfb57a08366c88e44a9500a78490e0053428605afacb0e99b582bea4445f2b910524d952216c74c16f90e022a33dbf15de6a128dc1c9ea1fab158c46eab88e");

  Botan::BigInt paramA(strA);
  std::cout << "A_16: " << std::hex << paramA << std::endl;
  Botan::SymmetricKey token = session.step2(paramA);

  std::cout << "clientKey: " << agree.second.as_string() << std::endl;
  std::cout << "sessionKey: " << token.as_string() << std::endl;

  assert( agree.second.as_string() == token.as_string() );
  return 0;
}
