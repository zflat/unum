/*
* Botan 2.4.0 Amalgamation
* (C) 1999-2017 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "botan_all.h"
#include "botan_all_internal.h"

#include <iostream>

/*
* Algorithm Identifier
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const OID& alg_id,
                                         const std::vector<uint8_t>& param) : oid(alg_id), parameters(param)
   {}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const std::string& alg_id,
                                         const std::vector<uint8_t>& param) : oid(OIDS::lookup(alg_id)), parameters(param)
   {}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const OID& alg_id,
                                         Encoding_Option option) : oid(alg_id), parameters()
   {
   const uint8_t DER_NULL[] = { 0x05, 0x00 };

   if(option == USE_NULL_PARAM)
      parameters += std::pair<const uint8_t*, size_t>(DER_NULL, sizeof(DER_NULL));
   }

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const std::string& alg_id,
                                         Encoding_Option option) : oid(OIDS::lookup(alg_id)), parameters()
   {
   const uint8_t DER_NULL[] = { 0x05, 0x00 };

   if(option == USE_NULL_PARAM)
      parameters += std::pair<const uint8_t*, size_t>(DER_NULL, sizeof(DER_NULL));
   }

/*
* Compare two AlgorithmIdentifiers
*/
namespace {

bool param_null_or_empty(const std::vector<uint8_t>& p)
   {
   if(p.size() == 2 && (p[0] == 0x05) && (p[1] == 0x00))
      return true;
   return p.empty();
   }

}

bool operator==(const AlgorithmIdentifier& a1, const AlgorithmIdentifier& a2)
   {
   if(a1.oid != a2.oid)
      return false;

   if(param_null_or_empty(a1.parameters) &&
      param_null_or_empty(a2.parameters))
      return true;

   return (a1.parameters == a2.parameters);
   }

/*
* Compare two AlgorithmIdentifiers
*/
bool operator!=(const AlgorithmIdentifier& a1, const AlgorithmIdentifier& a2)
   {
   return !(a1 == a2);
   }

/*
* DER encode an AlgorithmIdentifier
*/
void AlgorithmIdentifier::encode_into(DER_Encoder& codec) const
   {
   codec.start_cons(SEQUENCE)
      .encode(oid)
      .raw_bytes(parameters)
   .end_cons();
   }

/*
* Decode a BER encoded AlgorithmIdentifier
*/
void AlgorithmIdentifier::decode_from(BER_Decoder& codec)
   {
   codec.start_cons(SEQUENCE)
      .decode(oid)
      .raw_bytes(parameters)
   .end_cons();
   }

}
/*
* Attribute
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Create an Attribute
*/
Attribute::Attribute(const OID& attr_oid, const std::vector<uint8_t>& attr_value) : oid(attr_oid), parameters(attr_value)
   {}

/*
* Create an Attribute
*/
Attribute::Attribute(const std::string& attr_oid,
                     const std::vector<uint8_t>& attr_value) : oid(OIDS::lookup(attr_oid)), parameters(attr_value)
   {}

/*
* DER encode a Attribute
*/
void Attribute::encode_into(DER_Encoder& codec) const
   {
   codec.start_cons(SEQUENCE)
      .encode(oid)
      .start_cons(SET)
         .raw_bytes(parameters)
      .end_cons()
   .end_cons();
   }

/*
* Decode a BER encoded Attribute
*/
void Attribute::decode_from(BER_Decoder& codec)
   {
   codec.start_cons(SEQUENCE)
      .decode(oid)
      .start_cons(SET)
         .raw_bytes(parameters)
      .end_cons()
   .end_cons();
   }

}
/*
* ASN.1 Internals
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

std::string asn1_tag_to_string(ASN1_Tag type)
   {
   switch(type)
      {
      case Botan::PRINTABLE_STRING:
         return "PRINTABLE STRING";

      case Botan::NUMERIC_STRING:
         return "NUMERIC STRING";

      case Botan::IA5_STRING:
         return "IA5 STRING";

      case Botan::T61_STRING:
         return "T61 STRING";

      case Botan::UTF8_STRING:
         return "UTF8 STRING";

      case Botan::VISIBLE_STRING:
         return "VISIBLE STRING";

      case Botan::BMP_STRING:
         return "BMP STRING";

      case Botan::UTC_TIME:
         return "UTC TIME";

      case Botan::GENERALIZED_TIME:
         return "GENERALIZED TIME";

      case Botan::OCTET_STRING:
         return "OCTET STRING";

      case Botan::BIT_STRING:
         return "BIT STRING";

      case Botan::ENUMERATED:
         return "ENUMERATED";

      case Botan::INTEGER:
         return "INTEGER";

      case Botan::NULL_TAG:
         return "NULL";

      case Botan::OBJECT_ID:
         return "OBJECT";

      case Botan::BOOLEAN:
         return "BOOLEAN";

      default:
         return "TAG(" + std::to_string(static_cast<size_t>(type)) + ")";
      }
   }

/*
* BER Decoding Exceptions
*/
BER_Decoding_Error::BER_Decoding_Error(const std::string& str) :
   Decoding_Error("BER: " + str) {}

BER_Bad_Tag::BER_Bad_Tag(const std::string& str, ASN1_Tag tag) :
      BER_Decoding_Error(str + ": " + std::to_string(tag)) {}

BER_Bad_Tag::BER_Bad_Tag(const std::string& str,
                         ASN1_Tag tag1, ASN1_Tag tag2) :
   BER_Decoding_Error(str + ": " + std::to_string(tag1) + "/" + std::to_string(tag2)) {}

namespace ASN1 {

/*
* Put some arbitrary bytes into a SEQUENCE
*/
std::vector<uint8_t> put_in_sequence(const std::vector<uint8_t>& contents)
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .raw_bytes(contents)
      .end_cons()
   .get_contents_unlocked();
   }

/*
* Convert a BER object into a string object
*/
std::string to_string(const BER_Object& obj)
   {
   return to_string(obj.value);
   }

/*
* Do heuristic tests for BER data
*/
bool maybe_BER(DataSource& source)
   {
   uint8_t first_u8;
   if(!source.peek_byte(first_u8))
      {
      BOTAN_ASSERT_EQUAL(source.read_byte(first_u8), 0, "Expected EOF");
      throw Stream_IO_Error("ASN1::maybe_BER: Source was empty");
      }

   if(first_u8 == (SEQUENCE | CONSTRUCTED))
      return true;
   return false;
   }

}

}
/*
* ASN.1 OID
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* ASN.1 OID Constructor
*/
OID::OID(const std::string& oid_str)
   {
   if(!oid_str.empty())
      {
      try
         {
         m_id = parse_asn1_oid(oid_str);
         }
      catch(...)
         {
         throw Invalid_OID(oid_str);
         }

      if(m_id.size() < 2 || m_id[0] > 2)
         throw Invalid_OID(oid_str);
      if((m_id[0] == 0 || m_id[0] == 1) && m_id[1] > 39)
         throw Invalid_OID(oid_str);
      }
   }

/*
* Clear the current OID
*/
void OID::clear()
   {
   m_id.clear();
   }

/*
* Return this OID as a string
*/
std::string OID::as_string() const
   {
   std::string oid_str;
   for(size_t i = 0; i != m_id.size(); ++i)
      {
      oid_str += std::to_string(m_id[i]);
      if(i != m_id.size() - 1)
         oid_str += ".";
      }
   return oid_str;
   }

/*
* OID equality comparison
*/
bool OID::operator==(const OID& oid) const
   {
   if(m_id.size() != oid.m_id.size())
      return false;
   for(size_t i = 0; i != m_id.size(); ++i)
      if(m_id[i] != oid.m_id[i])
         return false;
   return true;
   }

/*
* Append another component to the OID
*/
OID& OID::operator+=(uint32_t component)
   {
   m_id.push_back(component);
   return (*this);
   }

/*
* Append another component to the OID
*/
OID operator+(const OID& oid, uint32_t component)
   {
   OID new_oid(oid);
   new_oid += component;
   return new_oid;
   }

/*
* OID inequality comparison
*/
bool operator!=(const OID& a, const OID& b)
   {
   return !(a == b);
   }

/*
* Compare two OIDs
*/
bool operator<(const OID& a, const OID& b)
   {
   const std::vector<uint32_t>& oid1 = a.get_id();
   const std::vector<uint32_t>& oid2 = b.get_id();

   if(oid1.size() < oid2.size())
      return true;
   if(oid1.size() > oid2.size())
      return false;
   for(size_t i = 0; i != oid1.size(); ++i)
      {
      if(oid1[i] < oid2[i])
         return true;
      if(oid1[i] > oid2[i])
         return false;
      }
   return false;
   }

/*
* DER encode an OBJECT IDENTIFIER
*/
void OID::encode_into(DER_Encoder& der) const
   {
   if(m_id.size() < 2)
      throw Invalid_Argument("OID::encode_into: OID is invalid");

   std::vector<uint8_t> encoding;

   if(m_id[0] > 2 || m_id[1] >= 40)
      throw Encoding_Error("Invalid OID prefix, cannot encode");

   encoding.push_back(static_cast<uint8_t>(40 * m_id[0] + m_id[1]));

   for(size_t i = 2; i != m_id.size(); ++i)
      {
      if(m_id[i] == 0)
         encoding.push_back(0);
      else
         {
         size_t blocks = high_bit(m_id[i]) + 6;
         blocks = (blocks - (blocks % 7)) / 7;

         BOTAN_ASSERT(blocks > 0, "Math works");

         for(size_t j = 0; j != blocks - 1; ++j)
            encoding.push_back(0x80 | ((m_id[i] >> 7*(blocks-j-1)) & 0x7F));
         encoding.push_back(m_id[i] & 0x7F);
         }
      }
   der.add_object(OBJECT_ID, UNIVERSAL, encoding);
   }

/*
* Decode a BER encoded OBJECT IDENTIFIER
*/
void OID::decode_from(BER_Decoder& decoder)
   {
   BER_Object obj = decoder.get_next_object();
   if(obj.type_tag != OBJECT_ID || obj.class_tag != UNIVERSAL)
      throw BER_Bad_Tag("Error decoding OID, unknown tag",
                        obj.type_tag, obj.class_tag);
   if(obj.value.size() < 2)
      throw BER_Decoding_Error("OID encoding is too short");


   clear();
   m_id.push_back(obj.value[0] / 40);
   m_id.push_back(obj.value[0] % 40);

   size_t i = 0;
   while(i != obj.value.size() - 1)
      {
      uint32_t component = 0;
      while(i != obj.value.size() - 1)
         {
         ++i;

         if(component >> (32-7))
            throw Decoding_Error("OID component overflow");

         component = (component << 7) + (obj.value[i] & 0x7F);

         if(!(obj.value[i] & 0x80))
            break;
         }
      m_id.push_back(component);
      }
   }

}
/*
* (C) 2014,2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <iomanip>
#include <sstream>
#include <cctype>

namespace Botan {

std::string ASN1_Pretty_Printer::print(const uint8_t in[], size_t len) const
   {
   std::ostringstream output;
   print_to_stream(output, in, len);
   return output.str();
   }

void ASN1_Pretty_Printer::print_to_stream(std::ostream& output,
                                          const uint8_t in[],
                                          size_t len) const
   {
   BER_Decoder dec(in, len);
   decode(output, dec, m_initial_level);
   }

std::string ASN1_Pretty_Printer::format_binary(const std::vector<uint8_t>& in) const
   {
   std::ostringstream out;

   size_t unprintable = 0;

   for(size_t i = 0; i != in.size(); ++i)
      {
      const int c = in[i];
      if(std::isalnum(c))
         {
         out << static_cast<char>(c);
         }
      else
         {
         out << "x" << std::hex << static_cast<int>(c) << std::dec;
         ++unprintable;
         if(unprintable >= in.size() / 4)
            {
            return hex_encode(in);
            }
         }
      }

   return out.str();
   }

void ASN1_Pretty_Printer::emit(std::ostream& output,
                               const std::string& type,
                               size_t level, size_t length,
                               const std::string& value) const
   {
   std::ostringstream oss;

   oss << "  d=" << std::setw(2) << level
       << ", l=" << std::setw(4) << length << ":"
       << std::string(level + 1, ' ') << type;

   bool should_skip = false;

   if(value.length() > m_print_limit)
      {
      should_skip = true;
      }

   if((type == "OCTET STRING" || type == "BIT STRING") && value.length() > m_print_binary_limit)
      {
      should_skip = true;
      }

   const std::string s = oss.str();

   output << s;

   if(value != "" && !should_skip)
      {
      const size_t spaces_to_align =
         (s.size() >= m_value_column) ? 1 : (m_value_column - s.size());

      output << std::string(spaces_to_align, ' ') << value;
      }

   output << "\n";
   }

void ASN1_Pretty_Printer::decode(std::ostream& output,
                                 BER_Decoder& decoder,
                                 size_t level) const
   {
   BER_Object obj = decoder.get_next_object();

   while(obj.type_tag != NO_OBJECT)
      {
      const ASN1_Tag type_tag = obj.type_tag;
      const ASN1_Tag class_tag = obj.class_tag;
      const size_t length = obj.value.size();

      /* hack to insert the tag+length back in front of the stuff now
         that we've gotten the type info */
      DER_Encoder encoder;
      encoder.add_object(type_tag, class_tag, obj.value);
      std::vector<uint8_t> bits = encoder.get_contents_unlocked();

      BER_Decoder data(bits);

      if(class_tag & CONSTRUCTED)
         {
         BER_Decoder cons_info(obj.value);
         if(type_tag == SEQUENCE)
            {
            emit(output, "SEQUENCE", level, length);
            decode(output, cons_info, level + 1); // recurse
            }
         else if(type_tag == SET)
            {
            emit(output, "SET", level, length);
            decode(output, cons_info, level + 1); // recurse
            }
         else
            {
            std::string name;

            if((class_tag & APPLICATION) || (class_tag & CONTEXT_SPECIFIC))
               {
               name = "cons [" + std::to_string(type_tag) + "]";

               if(class_tag & APPLICATION)
                  {
                  name += " appl";
                  }
               if(class_tag & CONTEXT_SPECIFIC)
                  {
                  name += " context";
                  }
               }
            else
               {
               name = asn1_tag_to_string(type_tag) + " (cons)";
               }

            emit(output, name, level, length);
            decode(output, cons_info, level + 1); // recurse
            }
         }
      else if((class_tag & APPLICATION) || (class_tag & CONTEXT_SPECIFIC))
         {
         if(m_print_context_specific)
            {
            try
               {
               std::vector<uint8_t> inner_bits;
               data.decode(inner_bits, type_tag);
               BER_Decoder inner(inner_bits);
               decode(output, inner, level + 1); // recurse
               }
            catch(...)
               {
               emit(output, "[" + std::to_string(type_tag) + "]", level, length, format_binary(bits));
               }
            }
         else
            {
            emit(output, "[" + std::to_string(type_tag) + "]", level, length, format_binary(bits));
            }
         }
      else if(type_tag == OBJECT_ID)
         {
         OID oid;
         data.decode(oid);

         std::string out = OIDS::lookup(oid);
         if(out.empty())
            {
            out = oid.as_string();
            }
         else
            {
            out += " [" + oid.as_string() + "]";
            }

         emit(output, asn1_tag_to_string(type_tag), level, length, out);
         }
      else if(type_tag == INTEGER || type_tag == ENUMERATED)
         {
         BigInt number;

         if(type_tag == INTEGER)
            {
            data.decode(number);
            }
         else if(type_tag == ENUMERATED)
            {
            data.decode(number, ENUMERATED, class_tag);
            }

         std::vector<uint8_t> rep;

         /* If it's small, it's probably a number, not a hash */
         if(number.bits() <= 20)
            {
            rep = BigInt::encode(number, BigInt::Decimal);
            }
         else
            {
            rep = BigInt::encode(number, BigInt::Hexadecimal);
            }

         std::string str;
         for(size_t i = 0; i != rep.size(); ++i)
            {
            str += static_cast<char>(rep[i]);
            }

         emit(output, asn1_tag_to_string(type_tag), level, length, str);
         }
      else if(type_tag == BOOLEAN)
         {
         bool boolean;
         data.decode(boolean);
         emit(output, asn1_tag_to_string(type_tag), level, length, (boolean ? "true" : "false"));
         }
      else if(type_tag == NULL_TAG)
         {
         emit(output, asn1_tag_to_string(type_tag), level, length);
         }
      else if(type_tag == OCTET_STRING || type_tag == BIT_STRING)
         {
         std::vector<uint8_t> decoded_bits;
         data.decode(decoded_bits, type_tag);

         try
            {
            BER_Decoder inner(decoded_bits);
            decode(output, inner, level + 1);
            }
         catch(...)
            {
            emit(output, asn1_tag_to_string(type_tag), level, length, format_binary(decoded_bits));
            }
         }
      else if(ASN1_String::is_string_type(type_tag))
         {
         ASN1_String str;
         data.decode(str);
         emit(output, asn1_tag_to_string(type_tag), level, length, str.value());
         }
      else if(type_tag == UTC_TIME || type_tag == GENERALIZED_TIME)
         {
         X509_Time time;
         data.decode(time);
         emit(output, asn1_tag_to_string(type_tag), level, length, time.readable_string());
         }
      else
         {
         output << "Unknown ASN.1 tag class=" << static_cast<int>(class_tag)
                << " type=" << static_cast<int>(type_tag) << "\n";;
         }

      obj = decoder.get_next_object();
      }
   }

}
/*
* Simple ASN.1 String Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

/*
* Choose an encoding for the string
*/
ASN1_Tag choose_encoding(const std::string& str)
   {
   static const uint8_t IS_PRINTABLE[256] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
      0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

   for(size_t i = 0; i != str.size(); ++i)
      {
      if(!IS_PRINTABLE[static_cast<uint8_t>(str[i])])
         {
         return UTF8_STRING;
         }
      }
   return PRINTABLE_STRING;
   }

void assert_is_string_type(ASN1_Tag tag)
   {
   if(!ASN1_String::is_string_type(tag))
      {
      throw Invalid_Argument("ASN1_String: Unknown string type " +
                             std::to_string(tag));
      }
   }

}

//static
bool ASN1_String::is_string_type(ASN1_Tag tag)
   {
   return (tag == NUMERIC_STRING ||
           tag == PRINTABLE_STRING ||
           tag == VISIBLE_STRING ||
           tag == T61_STRING ||
           tag == IA5_STRING ||
           tag == UTF8_STRING ||
           tag == BMP_STRING ||
           tag == UNIVERSAL_STRING);
   }


/*
* Create an ASN1_String
*/
ASN1_String::ASN1_String(const std::string& str, ASN1_Tag t) : m_utf8_str(str), m_tag(t)
   {
   if(m_tag == DIRECTORY_STRING)
      {
      m_tag = choose_encoding(m_utf8_str);
      }

   assert_is_string_type(m_tag);
   }

/*
* Create an ASN1_String
*/
ASN1_String::ASN1_String(const std::string& str) :
   m_utf8_str(str),
   m_tag(choose_encoding(m_utf8_str))
   {}

/*
* Return this string in ISO 8859-1 encoding
*/
std::string ASN1_String::iso_8859() const
   {
   return utf8_to_latin1(m_utf8_str);
   }

/*
* DER encode an ASN1_String
*/
void ASN1_String::encode_into(DER_Encoder& encoder) const
   {
   if(m_data.empty())
      {
      encoder.add_object(tagging(), UNIVERSAL, m_utf8_str);
      }
   else
      {
      // If this string was decoded, reserialize using original encoding
      encoder.add_object(tagging(), UNIVERSAL, m_data.data(), m_data.size());
      }
   }

/*
* Decode a BER encoded ASN1_String
*/
void ASN1_String::decode_from(BER_Decoder& source)
   {
   BER_Object obj = source.get_next_object();

   assert_is_string_type(obj.type_tag);

   m_tag = obj.type_tag;
   m_data.assign(obj.value.begin(), obj.value.end());

   if(m_tag == BMP_STRING)
      {
      m_utf8_str = ucs2_to_utf8(m_data.data(), m_data.size());
      }
   else if(m_tag == UNIVERSAL_STRING)
      {
      m_utf8_str = ucs4_to_utf8(m_data.data(), m_data.size());
      }
   else
      {
      // All other supported string types are UTF-8 or some subset thereof
      m_utf8_str = ASN1::to_string(obj);
      }
   }

}
/*
* X.509 Time Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

X509_Time::X509_Time(const std::chrono::system_clock::time_point& time)
   {
   calendar_point cal = calendar_value(time);

   m_year   = cal.get_year();
   m_month  = cal.get_month();
   m_day    = cal.get_day();
   m_hour   = cal.get_hour();
   m_minute = cal.get_minutes();
   m_second = cal.get_seconds();

   m_tag = (m_year >= 2050) ? GENERALIZED_TIME : UTC_TIME;
   }

X509_Time::X509_Time(const std::string& t_spec, ASN1_Tag tag)
   {
   set_to(t_spec, tag);
   }

void X509_Time::encode_into(DER_Encoder& der) const
   {
   if(m_tag != GENERALIZED_TIME && m_tag != UTC_TIME)
      throw Invalid_Argument("X509_Time: Bad encoding tag");

   der.add_object(m_tag, UNIVERSAL, to_string());
   }

void X509_Time::decode_from(BER_Decoder& source)
   {
   BER_Object ber_time = source.get_next_object();

   set_to(ASN1::to_string(ber_time), ber_time.type_tag);
   }

std::string X509_Time::to_string() const
   {
   if(time_is_set() == false)
      throw Invalid_State("X509_Time::as_string: No time set");

   uint32_t full_year = m_year;

   if(m_tag == UTC_TIME)
      {
      if(m_year < 1950 || m_year >= 2050)
         throw Encoding_Error("X509_Time: The time " + readable_string() +
                              " cannot be encoded as a UTCTime");

      full_year = (m_year >= 2000) ? (m_year - 2000) : (m_year - 1900);
      }

   const uint64_t YEAR_FACTOR = 10000000000ULL;
   const uint64_t MON_FACTOR  = 100000000;
   const uint64_t DAY_FACTOR  = 1000000;
   const uint64_t HOUR_FACTOR = 10000;
   const uint64_t MIN_FACTOR  = 100;

   const uint64_t int_repr =
      YEAR_FACTOR * full_year +
      MON_FACTOR * m_month +
      DAY_FACTOR * m_day +
      HOUR_FACTOR * m_hour +
      MIN_FACTOR * m_minute +
      m_second;

   std::string repr = std::to_string(int_repr) + "Z";

   uint32_t desired_size = (m_tag == UTC_TIME) ? 13 : 15;

   while(repr.size() < desired_size)
      repr = "0" + repr;

   return repr;
   }

std::string X509_Time::readable_string() const
   {
   if(time_is_set() == false)
      throw Invalid_State("X509_Time::readable_string: No time set");

   // desired format: "%04d/%02d/%02d %02d:%02d:%02d UTC"
   std::stringstream output;
   output << std::setfill('0')
          << std::setw(4) << m_year << "/"
          << std::setw(2) << m_month << "/"
          << std::setw(2) << m_day
          << " "
          << std::setw(2) << m_hour << ":"
          << std::setw(2) << m_minute << ":"
          << std::setw(2) << m_second
          << " UTC";

   return output.str();
   }

bool X509_Time::time_is_set() const
   {
   return (m_year != 0);
   }

int32_t X509_Time::cmp(const X509_Time& other) const
   {
   if(time_is_set() == false)
      throw Invalid_State("X509_Time::cmp: No time set");

   const int32_t EARLIER = -1, LATER = 1, SAME_TIME = 0;

   if(m_year < other.m_year)     return EARLIER;
   if(m_year > other.m_year)     return LATER;
   if(m_month < other.m_month)   return EARLIER;
   if(m_month > other.m_month)   return LATER;
   if(m_day < other.m_day)       return EARLIER;
   if(m_day > other.m_day)       return LATER;
   if(m_hour < other.m_hour)     return EARLIER;
   if(m_hour > other.m_hour)     return LATER;
   if(m_minute < other.m_minute) return EARLIER;
   if(m_minute > other.m_minute) return LATER;
   if(m_second < other.m_second) return EARLIER;
   if(m_second > other.m_second) return LATER;

   return SAME_TIME;
   }

void X509_Time::set_to(const std::string& t_spec, ASN1_Tag spec_tag)
   {
   if(spec_tag == UTC_OR_GENERALIZED_TIME)
      {
      try
         {
         set_to(t_spec, GENERALIZED_TIME);
         return;
         }
      catch(Invalid_Argument&) {} // Not a generalized time. Continue

      try
         {
         set_to(t_spec, UTC_TIME);
         return;
         }
      catch(Invalid_Argument&) {} // Not a UTC time. Continue

      throw Invalid_Argument("Time string could not be parsed as GeneralizedTime or UTCTime.");
      }

   BOTAN_ASSERT(spec_tag == UTC_TIME || spec_tag == GENERALIZED_TIME, "Invalid tag.");

   if(t_spec.empty())
      throw Invalid_Argument("Time string must not be empty.");

   if(t_spec.back() != 'Z')
      throw Unsupported_Argument("Botan does not support times with timezones other than Z: " + t_spec);

   if(spec_tag == GENERALIZED_TIME)
      {
      if(t_spec.size() != 15)
         throw Invalid_Argument("Invalid GeneralizedTime string: '" + t_spec + "'");
      }
   else if(spec_tag == UTC_TIME)
      {
      if(t_spec.size() != 13)
         throw Invalid_Argument("Invalid UTCTime string: '" + t_spec + "'");
      }

   const size_t YEAR_SIZE = (spec_tag == UTC_TIME) ? 2 : 4;

   std::vector<std::string> params;
   std::string current;

   for(size_t j = 0; j != YEAR_SIZE; ++j)
      current += t_spec[j];
   params.push_back(current);
   current.clear();

   for(size_t j = YEAR_SIZE; j != t_spec.size() - 1; ++j)
      {
      current += t_spec[j];
      if(current.size() == 2)
         {
         params.push_back(current);
         current.clear();
         }
      }

   m_year   = to_u32bit(params[0]);
   m_month  = to_u32bit(params[1]);
   m_day    = to_u32bit(params[2]);
   m_hour   = to_u32bit(params[3]);
   m_minute = to_u32bit(params[4]);
   m_second = (params.size() == 6) ? to_u32bit(params[5]) : 0;
   m_tag    = spec_tag;

   if(spec_tag == UTC_TIME)
      {
      if(m_year >= 50) m_year += 1900;
      else             m_year += 2000;
      }

   if(!passes_sanity_check())
      throw Invalid_Argument("Time did not pass sanity check: " + t_spec);
   }

/*
* Do a general sanity check on the time
*/
bool X509_Time::passes_sanity_check() const
   {
   if(m_year < 1950 || m_year > 2100)
      return false;
   if(m_month == 0 || m_month > 12)
      return false;
   if(m_day == 0 || m_day > 31)
      return false;
   if(m_hour >= 24 || m_minute > 60 || m_second > 60)
      return false;

   if (m_tag == UTC_TIME)
      {
      /*
      UTCTime limits the value of components such that leap seconds
      are not covered. See "UNIVERSAL 23" in "Information technology
      Abstract Syntax Notation One (ASN.1): Specification of basic notation"

      http://www.itu.int/ITU-T/studygroups/com17/languages/
      */
      if (m_hour > 23 || m_minute > 59 || m_second > 59)
         {
         return false;
         }
      }

   return true;
   }

std::chrono::system_clock::time_point X509_Time::to_std_timepoint() const
   {
   return calendar_point(m_year, m_month, m_day, m_hour, m_minute, m_second).to_std_timepoint();
   }

/*
* Compare two X509_Times for in various ways
*/
bool operator==(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) == 0); }
bool operator!=(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) != 0); }

bool operator<=(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) <= 0); }
bool operator>=(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) >= 0); }

bool operator<(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) < 0); }
bool operator>(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) > 0); }

}
/*
* BER Decoder
* (C) 1999-2008,2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

/*
* This value is somewhat arbitrary. OpenSSL allows up to 128 nested
* indefinite length sequences. If you increase this, also increase the
* limit in the test in test_asn1.cpp
*/
const size_t ALLOWED_EOC_NESTINGS = 16;

/*
* BER decode an ASN.1 type tag
*/
size_t decode_tag(DataSource* ber, ASN1_Tag& type_tag, ASN1_Tag& class_tag)
   {
   uint8_t b;
   if(!ber->read_byte(b))
      {
      class_tag = type_tag = NO_OBJECT;
      return 0;
      }

   if((b & 0x1F) != 0x1F)
      {
      type_tag = ASN1_Tag(b & 0x1F);
      class_tag = ASN1_Tag(b & 0xE0);
      return 1;
      }

   size_t tag_bytes = 1;
   class_tag = ASN1_Tag(b & 0xE0);

   size_t tag_buf = 0;
   while(true)
      {
      if(!ber->read_byte(b))
         throw BER_Decoding_Error("Long-form tag truncated");
      if(tag_buf & 0xFF000000)
         throw BER_Decoding_Error("Long-form tag overflowed 32 bits");
      ++tag_bytes;
      tag_buf = (tag_buf << 7) | (b & 0x7F);
      if((b & 0x80) == 0) break;
      }
   type_tag = ASN1_Tag(tag_buf);
   return tag_bytes;
   }

/*
* Find the EOC marker
*/
size_t find_eoc(DataSource* src, size_t allow_indef);

/*
* BER decode an ASN.1 length field
*/
size_t decode_length(DataSource* ber, size_t& field_size, size_t allow_indef)
   {
   uint8_t b;
   if(!ber->read_byte(b))
      throw BER_Decoding_Error("Length field not found");
   field_size = 1;
   if((b & 0x80) == 0)
      return b;

   field_size += (b & 0x7F);
   if(field_size > 5)
      throw BER_Decoding_Error("Length field is too large");

   if(field_size == 1)
      {
      if(allow_indef == 0)
         {
         throw BER_Decoding_Error("Nested EOC markers too deep, rejecting to avoid stack exhaustion");
         }
      else
         {
         return find_eoc(ber, allow_indef - 1);
         }
      }

   size_t length = 0;

   for(size_t i = 0; i != field_size - 1; ++i)
      {
      if(get_byte(0, length) != 0)
         throw BER_Decoding_Error("Field length overflow");
      if(!ber->read_byte(b))
         throw BER_Decoding_Error("Corrupted length field");
      length = (length << 8) | b;
      }
   return length;
   }

/*
* Find the EOC marker
*/
size_t find_eoc(DataSource* ber, size_t allow_indef)
   {
   secure_vector<uint8_t> buffer(DEFAULT_BUFFERSIZE), data;

   while(true)
      {
      const size_t got = ber->peek(buffer.data(), buffer.size(), data.size());
      if(got == 0)
         break;

      data += std::make_pair(buffer.data(), got);
      }

   DataSource_Memory source(data);
   data.clear();

   size_t length = 0;
   while(true)
      {
      ASN1_Tag type_tag, class_tag;
      size_t tag_size = decode_tag(&source, type_tag, class_tag);
      if(type_tag == NO_OBJECT)
         break;

      size_t length_size = 0;
      size_t item_size = decode_length(&source, length_size, allow_indef);
      source.discard_next(item_size);

      length = BOTAN_CHECKED_ADD(length, item_size);
      length = BOTAN_CHECKED_ADD(length, tag_size);
      length = BOTAN_CHECKED_ADD(length, length_size);

      if(type_tag == EOC && class_tag == UNIVERSAL)
         break;
      }
   return length;
   }

}

/*
* Check a type invariant on BER data
*/
void BER_Object::assert_is_a(ASN1_Tag type_tag_, ASN1_Tag class_tag_)
   {
   if(type_tag != type_tag_ || class_tag != class_tag_)
      throw BER_Decoding_Error("Tag mismatch when decoding got " +
                               std::to_string(type_tag) + "/" +
                               std::to_string(class_tag) + " expected " +
                               std::to_string(type_tag_) + "/" +
                               std::to_string(class_tag_));
   }

/*
* Check if more objects are there
*/
bool BER_Decoder::more_items() const
   {
   if(m_source->end_of_data() && (m_pushed.type_tag == NO_OBJECT))
      return false;
   return true;
   }

/*
* Verify that no bytes remain in the source
*/
BER_Decoder& BER_Decoder::verify_end()
   {
   if(!m_source->end_of_data() || (m_pushed.type_tag != NO_OBJECT))
      throw Invalid_State("BER_Decoder::verify_end called, but data remains");
   return (*this);
   }

/*
* Save all the bytes remaining in the source
*/
BER_Decoder& BER_Decoder::raw_bytes(secure_vector<uint8_t>& out)
   {
   out.clear();
   uint8_t buf;
   while(m_source->read_byte(buf))
      out.push_back(buf);
   return (*this);
   }

BER_Decoder& BER_Decoder::raw_bytes(std::vector<uint8_t>& out)
   {
   out.clear();
   uint8_t buf;
   while(m_source->read_byte(buf))
      out.push_back(buf);
   return (*this);
   }

/*
* Discard all the bytes remaining in the source
*/
BER_Decoder& BER_Decoder::discard_remaining()
   {
   uint8_t buf;
   while(m_source->read_byte(buf))
      ;
   return (*this);
   }

/*
* Return the BER encoding of the next object
*/
BER_Object BER_Decoder::get_next_object()
   {
   BER_Object next;

   if(m_pushed.type_tag != NO_OBJECT)
      {
      next = m_pushed;
      m_pushed.class_tag = m_pushed.type_tag = NO_OBJECT;
      return next;
      }

   for(;;)
      {
      decode_tag(m_source, next.type_tag, next.class_tag);
      if(next.type_tag == NO_OBJECT)
         return next;

      size_t field_size;
      const size_t length = decode_length(m_source, field_size, ALLOWED_EOC_NESTINGS);
      if(!m_source->check_available(length))
         throw BER_Decoding_Error("Value truncated");

      next.value.resize(length);
      if(m_source->read(next.value.data(), length) != length)
         throw BER_Decoding_Error("Value truncated");

      if(next.type_tag == EOC && next.class_tag == UNIVERSAL)
         continue;
      else
         break;
      }

   return next;
   }

BER_Decoder& BER_Decoder::get_next(BER_Object& ber)
   {
   ber = get_next_object();
   return (*this);
   }

/*
* Push a object back into the stream
*/
void BER_Decoder::push_back(const BER_Object& obj)
   {
   if(m_pushed.type_tag != NO_OBJECT)
      throw Invalid_State("BER_Decoder: Only one push back is allowed");
   m_pushed = obj;
   }

/*
* Begin decoding a CONSTRUCTED type
*/
BER_Decoder BER_Decoder::start_cons(ASN1_Tag type_tag,
                                    ASN1_Tag class_tag)
   {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, ASN1_Tag(class_tag | CONSTRUCTED));

   BER_Decoder result(obj.value.data(), obj.value.size());
   result.m_parent = this;
   return result;
   }

/*
* Finish decoding a CONSTRUCTED type
*/
BER_Decoder& BER_Decoder::end_cons()
   {
   if(!m_parent)
      throw Invalid_State("BER_Decoder::end_cons called with NULL parent");
   if(!m_source->end_of_data())
      throw Decoding_Error("BER_Decoder::end_cons called with data left");
   return (*m_parent);
   }

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(DataSource& src)
   {
   m_source = &src;
   m_pushed.type_tag = m_pushed.class_tag = NO_OBJECT;
   m_parent = nullptr;
   }

/*
* BER_Decoder Constructor
 */
BER_Decoder::BER_Decoder(const uint8_t data[], size_t length)
   {
   m_data_src.reset(new DataSource_Memory(data, length));
   m_source = m_data_src.get();
   m_pushed.type_tag = m_pushed.class_tag = NO_OBJECT;
   m_parent = nullptr;
   }

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(const secure_vector<uint8_t>& data)
   {
   m_data_src.reset(new DataSource_Memory(data));
   m_source = m_data_src.get();
   m_pushed.type_tag = m_pushed.class_tag = NO_OBJECT;
   m_parent = nullptr;
   }

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(const std::vector<uint8_t>& data)
   {
   m_data_src.reset(new DataSource_Memory(data.data(), data.size()));
   m_source = m_data_src.get();
   m_pushed.type_tag = m_pushed.class_tag = NO_OBJECT;
   m_parent = nullptr;
   }

/*
* BER_Decoder Copy Constructor
*/
BER_Decoder::BER_Decoder(const BER_Decoder& other)
   {
   m_source = other.m_source;

   // take ownership
   std::swap(m_data_src, other.m_data_src);
   m_pushed.type_tag = m_pushed.class_tag = NO_OBJECT;
   m_parent = other.m_parent;
   }

/*
* Request for an object to decode itself
*/
BER_Decoder& BER_Decoder::decode(ASN1_Object& obj,
                                 ASN1_Tag, ASN1_Tag)
   {
   obj.decode_from(*this);
   return (*this);
   }

/*
* Decode a BER encoded NULL
*/
BER_Decoder& BER_Decoder::decode_null()
   {
   BER_Object obj = get_next_object();
   obj.assert_is_a(NULL_TAG, UNIVERSAL);
   if(obj.value.size())
      throw BER_Decoding_Error("NULL object had nonzero size");
   return (*this);
   }

/*
* Decode a BER encoded BOOLEAN
*/
BER_Decoder& BER_Decoder::decode(bool& out)
   {
   return decode(out, BOOLEAN, UNIVERSAL);
   }

/*
* Decode a small BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(size_t& out)
   {
   return decode(out, INTEGER, UNIVERSAL);
   }

/*
* Decode a BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(BigInt& out)
   {
   return decode(out, INTEGER, UNIVERSAL);
   }

BER_Decoder& BER_Decoder::decode_octet_string_bigint(BigInt& out)
   {
   secure_vector<uint8_t> out_vec;
   decode(out_vec, OCTET_STRING);
   out = BigInt::decode(out_vec.data(), out_vec.size());
   return (*this);
   }

std::vector<uint8_t> BER_Decoder::get_next_octet_string()
   {
   std::vector<uint8_t> out_vec;
   decode(out_vec, OCTET_STRING);
   return out_vec;
   }

/*
* Decode a BER encoded BOOLEAN
*/
BER_Decoder& BER_Decoder::decode(bool& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(obj.value.size() != 1)
      throw BER_Decoding_Error("BER boolean value had invalid size");

   out = (obj.value[0]) ? true : false;
   return (*this);
   }

/*
* Decode a small BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(size_t& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BigInt integer;
   decode(integer, type_tag, class_tag);

   if(integer.bits() > 32)
      throw BER_Decoding_Error("Decoded integer value larger than expected");

   out = 0;
   for(size_t i = 0; i != 4; ++i)
      out = (out << 8) | integer.byte_at(3-i);

   return (*this);
   }

/*
* Decode a small BER encoded INTEGER
*/
uint64_t BER_Decoder::decode_constrained_integer(ASN1_Tag type_tag,
                                               ASN1_Tag class_tag,
                                               size_t T_bytes)
   {
   if(T_bytes > 8)
      throw BER_Decoding_Error("Can't decode small integer over 8 bytes");

   BigInt integer;
   decode(integer, type_tag, class_tag);

   if(integer.bits() > 8*T_bytes)
      throw BER_Decoding_Error("Decoded integer value larger than expected");

   uint64_t out = 0;
   for(size_t i = 0; i != 8; ++i)
      out = (out << 8) | integer.byte_at(7-i);

   return out;
   }

/*
* Decode a BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(BigInt& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(obj.value.empty())
      out = 0;
   else
      {
      const bool negative = (obj.value[0] & 0x80) ? true : false;

      if(negative)
         {
         for(size_t i = obj.value.size(); i > 0; --i)
            if(obj.value[i-1]--)
               break;
         for(size_t i = 0; i != obj.value.size(); ++i)
            obj.value[i] = ~obj.value[i];
         }

      out = BigInt(&obj.value[0], obj.value.size());

      if(negative)
         out.flip_sign();
      }

   return (*this);
   }

/*
* BER decode a BIT STRING or OCTET STRING
*/
BER_Decoder& BER_Decoder::decode(secure_vector<uint8_t>& out, ASN1_Tag real_type)
   {
   return decode(out, real_type, real_type, UNIVERSAL);
   }

/*
* BER decode a BIT STRING or OCTET STRING
*/
BER_Decoder& BER_Decoder::decode(std::vector<uint8_t>& out, ASN1_Tag real_type)
   {
   return decode(out, real_type, real_type, UNIVERSAL);
   }

/*
* BER decode a BIT STRING or OCTET STRING
*/
BER_Decoder& BER_Decoder::decode(secure_vector<uint8_t>& buffer,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(real_type != OCTET_STRING && real_type != BIT_STRING)
      throw BER_Bad_Tag("Bad tag for {BIT,OCTET} STRING", real_type);

   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(real_type == OCTET_STRING)
      buffer = obj.value;
   else
      {
      if(obj.value.empty())
         throw BER_Decoding_Error("Invalid BIT STRING");
      if(obj.value[0] >= 8)
         throw BER_Decoding_Error("Bad number of unused bits in BIT STRING");

      buffer.resize(obj.value.size() - 1);

      if(obj.value.size() > 1)
         copy_mem(buffer.data(), &obj.value[1], obj.value.size() - 1);
      }
   return (*this);
   }

BER_Decoder& BER_Decoder::decode(std::vector<uint8_t>& buffer,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(real_type != OCTET_STRING && real_type != BIT_STRING)
      throw BER_Bad_Tag("Bad tag for {BIT,OCTET} STRING", real_type);

   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(real_type == OCTET_STRING)
      buffer = unlock(obj.value);
   else
      {
      if(obj.value.empty())
         throw BER_Decoding_Error("Invalid BIT STRING");
      if(obj.value[0] >= 8)
         throw BER_Decoding_Error("Bad number of unused bits in BIT STRING");

      buffer.resize(obj.value.size() - 1);

      if(obj.value.size() > 1)
         copy_mem(buffer.data(), &obj.value[1], obj.value.size() - 1);
      }
   return (*this);
   }

}
/*
* DER Encoder
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

/*
* DER encode an ASN.1 type tag
*/
secure_vector<uint8_t> encode_tag(ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if((class_tag | 0xE0) != 0xE0)
      throw Encoding_Error("DER_Encoder: Invalid class tag " +
                           std::to_string(class_tag));

   secure_vector<uint8_t> encoded_tag;
   if(type_tag <= 30)
      encoded_tag.push_back(static_cast<uint8_t>(type_tag | class_tag));
   else
      {
      size_t blocks = high_bit(type_tag) + 6;
      blocks = (blocks - (blocks % 7)) / 7;

      BOTAN_ASSERT(blocks > 0, "Math works");

      encoded_tag.push_back(static_cast<uint8_t>(class_tag | 0x1F));
      for(size_t i = 0; i != blocks - 1; ++i)
         encoded_tag.push_back(0x80 | ((type_tag >> 7*(blocks-i-1)) & 0x7F));
      encoded_tag.push_back(type_tag & 0x7F);
      }

   return encoded_tag;
   }

/*
* DER encode an ASN.1 length field
*/
secure_vector<uint8_t> encode_length(size_t length)
   {
   secure_vector<uint8_t> encoded_length;
   if(length <= 127)
      encoded_length.push_back(static_cast<uint8_t>(length));
   else
      {
      const size_t bytes_needed = significant_bytes(length);

      encoded_length.push_back(static_cast<uint8_t>(0x80 | bytes_needed));

      for(size_t i = sizeof(length) - bytes_needed; i < sizeof(length); ++i)
         encoded_length.push_back(get_byte(i, length));
      }
   return encoded_length;
   }

}

/*
* Return the encoded SEQUENCE/SET
*/
secure_vector<uint8_t> DER_Encoder::DER_Sequence::get_contents()
   {
   const ASN1_Tag real_class_tag = ASN1_Tag(m_class_tag | CONSTRUCTED);

   if(m_type_tag == SET)
      {
      std::sort(m_set_contents.begin(), m_set_contents.end());
      for(size_t i = 0; i != m_set_contents.size(); ++i)
         m_contents += m_set_contents[i];
      m_set_contents.clear();
      }

   secure_vector<uint8_t> result;
   result += encode_tag(m_type_tag, real_class_tag);
   result += encode_length(m_contents.size());
   result += m_contents;
   m_contents.clear();

   return result;
   }

/*
* Add an encoded value to the SEQUENCE/SET
*/
void DER_Encoder::DER_Sequence::add_bytes(const uint8_t data[], size_t length)
   {
   if(m_type_tag == SET)
      m_set_contents.push_back(secure_vector<uint8_t>(data, data + length));
   else
      m_contents += std::make_pair(data, length);
   }

/*
* Return the type and class taggings
*/
ASN1_Tag DER_Encoder::DER_Sequence::tag_of() const
   {
   return ASN1_Tag(m_type_tag | m_class_tag);
   }

/*
* DER_Sequence Constructor
*/
DER_Encoder::DER_Sequence::DER_Sequence(ASN1_Tag t1, ASN1_Tag t2) :
   m_type_tag(t1), m_class_tag(t2)
   {
   }

/*
* Return the encoded contents
*/
secure_vector<uint8_t> DER_Encoder::get_contents()
   {
   if(m_subsequences.size() != 0)
      throw Invalid_State("DER_Encoder: Sequence hasn't been marked done");

   secure_vector<uint8_t> output;
   std::swap(output, m_contents);
   return output;
   }

/*
* Start a new ASN.1 SEQUENCE/SET/EXPLICIT
*/
DER_Encoder& DER_Encoder::start_cons(ASN1_Tag type_tag,
                                     ASN1_Tag class_tag)
   {
   m_subsequences.push_back(DER_Sequence(type_tag, class_tag));
   return (*this);
   }

/*
* Finish the current ASN.1 SEQUENCE/SET/EXPLICIT
*/
DER_Encoder& DER_Encoder::end_cons()
   {
   if(m_subsequences.empty())
      throw Invalid_State("DER_Encoder::end_cons: No such sequence");

   secure_vector<uint8_t> seq = m_subsequences[m_subsequences.size()-1].get_contents();
   m_subsequences.pop_back();
   raw_bytes(seq);
   return (*this);
   }

/*
* Start a new ASN.1 EXPLICIT encoding
*/
DER_Encoder& DER_Encoder::start_explicit(uint16_t type_no)
   {
   ASN1_Tag type_tag = static_cast<ASN1_Tag>(type_no);

   if(type_tag == SET)
      throw Internal_Error("DER_Encoder.start_explicit(SET); cannot perform");

   return start_cons(type_tag, CONTEXT_SPECIFIC);
   }

/*
* Finish the current ASN.1 EXPLICIT encoding
*/
DER_Encoder& DER_Encoder::end_explicit()
   {
   return end_cons();
   }

/*
* Write raw bytes into the stream
*/
DER_Encoder& DER_Encoder::raw_bytes(const secure_vector<uint8_t>& val)
   {
   return raw_bytes(val.data(), val.size());
   }

DER_Encoder& DER_Encoder::raw_bytes(const std::vector<uint8_t>& val)
   {
   return raw_bytes(val.data(), val.size());
   }

/*
* Write raw bytes into the stream
*/
DER_Encoder& DER_Encoder::raw_bytes(const uint8_t bytes[], size_t length)
   {
   if(m_subsequences.size())
      m_subsequences[m_subsequences.size()-1].add_bytes(bytes, length);
   else
      m_contents += std::make_pair(bytes, length);

   return (*this);
   }

/*
* Encode a NULL object
*/
DER_Encoder& DER_Encoder::encode_null()
   {
   return add_object(NULL_TAG, UNIVERSAL, nullptr, 0);
   }

/*
* DER encode a BOOLEAN
*/
DER_Encoder& DER_Encoder::encode(bool is_true)
   {
   return encode(is_true, BOOLEAN, UNIVERSAL);
   }

/*
* DER encode a small INTEGER
*/
DER_Encoder& DER_Encoder::encode(size_t n)
   {
   return encode(BigInt(n), INTEGER, UNIVERSAL);
   }

/*
* DER encode a small INTEGER
*/
DER_Encoder& DER_Encoder::encode(const BigInt& n)
   {
   return encode(n, INTEGER, UNIVERSAL);
   }

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(const secure_vector<uint8_t>& bytes,
                                 ASN1_Tag real_type)
   {
   return encode(bytes.data(), bytes.size(),
                 real_type, real_type, UNIVERSAL);
   }

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(const std::vector<uint8_t>& bytes,
                                 ASN1_Tag real_type)
   {
   return encode(bytes.data(), bytes.size(),
                 real_type, real_type, UNIVERSAL);
   }

/*
* Encode this object
*/
DER_Encoder& DER_Encoder::encode(const uint8_t bytes[], size_t length,
                                 ASN1_Tag real_type)
   {
   return encode(bytes, length, real_type, real_type, UNIVERSAL);
   }

/*
* DER encode a BOOLEAN
*/
DER_Encoder& DER_Encoder::encode(bool is_true,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   uint8_t val = is_true ? 0xFF : 0x00;
   return add_object(type_tag, class_tag, &val, 1);
   }

/*
* DER encode a small INTEGER
*/
DER_Encoder& DER_Encoder::encode(size_t n,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   return encode(BigInt(n), type_tag, class_tag);
   }

/*
* DER encode an INTEGER
*/
DER_Encoder& DER_Encoder::encode(const BigInt& n,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(n == 0)
      return add_object(type_tag, class_tag, 0);

   const size_t extra_zero = (n.bits() % 8 == 0) ? 1 : 0;
   secure_vector<uint8_t> contents(extra_zero + n.bytes());
   BigInt::encode(&contents[extra_zero], n);
   if(n < 0)
      {
      for(size_t i = 0; i != contents.size(); ++i)
         contents[i] = ~contents[i];
      for(size_t i = contents.size(); i > 0; --i)
         if(++contents[i-1])
            break;
      }

   return add_object(type_tag, class_tag, contents);
   }

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(const secure_vector<uint8_t>& bytes,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   return encode(bytes.data(), bytes.size(),
                 real_type, type_tag, class_tag);
   }

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(const std::vector<uint8_t>& bytes,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   return encode(bytes.data(), bytes.size(),
                 real_type, type_tag, class_tag);
   }

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(const uint8_t bytes[], size_t length,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(real_type != OCTET_STRING && real_type != BIT_STRING)
      throw Invalid_Argument("DER_Encoder: Invalid tag for byte/bit string");

   if(real_type == BIT_STRING)
      {
      secure_vector<uint8_t> encoded;
      encoded.push_back(0);
      encoded += std::make_pair(bytes, length);
      return add_object(type_tag, class_tag, encoded);
      }
   else
      return add_object(type_tag, class_tag, bytes, length);
   }

/*
* Conditionally write some values to the stream
*/
DER_Encoder& DER_Encoder::encode_if(bool cond, DER_Encoder& codec)
   {
   if(cond)
      return raw_bytes(codec.get_contents());
   return (*this);
   }

DER_Encoder& DER_Encoder::encode_if(bool cond, const ASN1_Object& obj)
   {
   if(cond)
      encode(obj);
   return (*this);
   }

/*
* Request for an object to encode itself
*/
DER_Encoder& DER_Encoder::encode(const ASN1_Object& obj)
   {
   obj.encode_into(*this);
   return (*this);
   }

/*
* Write the encoding of the byte(s)
*/
DER_Encoder& DER_Encoder::add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
                                     const uint8_t rep[], size_t length)
   {
   secure_vector<uint8_t> buffer;
   buffer += encode_tag(type_tag, class_tag);
   buffer += encode_length(length);
   buffer += std::make_pair(rep, length);

   return raw_bytes(buffer);
   }

/*
* Write the encoding of the byte(s)
*/
DER_Encoder& DER_Encoder::add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
                                     const std::string& rep_str)
   {
   const uint8_t* rep = cast_char_ptr_to_uint8(rep_str.data());
   const size_t rep_len = rep_str.size();
   return add_object(type_tag, class_tag, rep, rep_len);
   }

/*
* Write the encoding of the byte
*/
DER_Encoder& DER_Encoder::add_object(ASN1_Tag type_tag,
                                     ASN1_Tag class_tag, uint8_t rep)
   {
   return add_object(type_tag, class_tag, &rep, 1);
   }

}
/*
* OID maps
*
* This file was automatically generated by .\src\scripts\oids.py on 2017-10-19
*
* All manual edits to this file will be lost. Edit the script
* then regenerate this source file.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace OIDS {

std::string lookup(const OID& oid)
   {
   const std::string oid_str = oid.as_string();
   if(oid_str == "1.0.14888.3.0.5") return "ECKCDSA";
   if(oid_str == "1.2.156.10197.1.301") return "sm2p256v1";
   if(oid_str == "1.2.156.10197.1.301.1") return "SM2_Sig";
   if(oid_str == "1.2.156.10197.1.301.2") return "SM2_Kex";
   if(oid_str == "1.2.156.10197.1.301.3") return "SM2_Enc";
   if(oid_str == "1.2.156.10197.1.401") return "SM3";
   if(oid_str == "1.2.156.10197.1.504") return "RSA/EMSA3(SM3)";
   if(oid_str == "1.2.250.1.223.101.256.1") return "frp256v1";
   if(oid_str == "1.2.410.200004.1.100.4.3") return "ECKCDSA/EMSA1(SHA-1)";
   if(oid_str == "1.2.410.200004.1.100.4.4") return "ECKCDSA/EMSA1(SHA-224)";
   if(oid_str == "1.2.410.200004.1.100.4.5") return "ECKCDSA/EMSA1(SHA-256)";
   if(oid_str == "1.2.410.200004.1.4") return "SEED/CBC";
   if(oid_str == "1.2.643.2.2.19") return "GOST-34.10";
   if(oid_str == "1.2.643.2.2.3") return "GOST-34.10/EMSA1(GOST-R-34.11-94)";
   if(oid_str == "1.2.643.2.2.35.1") return "gost_256A";
   if(oid_str == "1.2.643.2.2.36.0") return "gost_256A";
   if(oid_str == "1.2.643.7.1.1.2.2") return "Streebog-256";
   if(oid_str == "1.2.643.7.1.1.2.3") return "Streebog-512";
   if(oid_str == "1.2.840.10040.4.1") return "DSA";
   if(oid_str == "1.2.840.10040.4.3") return "DSA/EMSA1(SHA-160)";
   if(oid_str == "1.2.840.10045.2.1") return "ECDSA";
   if(oid_str == "1.2.840.10045.3.1.1") return "secp192r1";
   if(oid_str == "1.2.840.10045.3.1.2") return "x962_p192v2";
   if(oid_str == "1.2.840.10045.3.1.3") return "x962_p192v3";
   if(oid_str == "1.2.840.10045.3.1.4") return "x962_p239v1";
   if(oid_str == "1.2.840.10045.3.1.5") return "x962_p239v2";
   if(oid_str == "1.2.840.10045.3.1.6") return "x962_p239v3";
   if(oid_str == "1.2.840.10045.3.1.7") return "secp256r1";
   if(oid_str == "1.2.840.10045.4.1") return "ECDSA/EMSA1(SHA-160)";
   if(oid_str == "1.2.840.10045.4.3.1") return "ECDSA/EMSA1(SHA-224)";
   if(oid_str == "1.2.840.10045.4.3.2") return "ECDSA/EMSA1(SHA-256)";
   if(oid_str == "1.2.840.10045.4.3.3") return "ECDSA/EMSA1(SHA-384)";
   if(oid_str == "1.2.840.10045.4.3.4") return "ECDSA/EMSA1(SHA-512)";
   if(oid_str == "1.2.840.10046.2.1") return "DH";
   if(oid_str == "1.2.840.113533.7.66.10") return "CAST-128/CBC";
   if(oid_str == "1.2.840.113533.7.66.15") return "KeyWrap.CAST-128";
   if(oid_str == "1.2.840.113549.1.1.1") return "RSA";
   if(oid_str == "1.2.840.113549.1.1.10") return "RSA/EMSA4";
   if(oid_str == "1.2.840.113549.1.1.11") return "RSA/EMSA3(SHA-256)";
   if(oid_str == "1.2.840.113549.1.1.12") return "RSA/EMSA3(SHA-384)";
   if(oid_str == "1.2.840.113549.1.1.13") return "RSA/EMSA3(SHA-512)";
   if(oid_str == "1.2.840.113549.1.1.14") return "RSA/EMSA3(SHA-224)";
   if(oid_str == "1.2.840.113549.1.1.16") return "RSA/EMSA3(SHA-512-256)";
   if(oid_str == "1.2.840.113549.1.1.4") return "RSA/EMSA3(MD5)";
   if(oid_str == "1.2.840.113549.1.1.5") return "RSA/EMSA3(SHA-160)";
   if(oid_str == "1.2.840.113549.1.1.7") return "RSA/OAEP";
   if(oid_str == "1.2.840.113549.1.1.8") return "MGF1";
   if(oid_str == "1.2.840.113549.1.5.12") return "PKCS5.PBKDF2";
   if(oid_str == "1.2.840.113549.1.5.13") return "PBE-PKCS5v20";
   if(oid_str == "1.2.840.113549.1.9.1") return "PKCS9.EmailAddress";
   if(oid_str == "1.2.840.113549.1.9.14") return "PKCS9.ExtensionRequest";
   if(oid_str == "1.2.840.113549.1.9.16.3.6") return "KeyWrap.TripleDES";
   if(oid_str == "1.2.840.113549.1.9.16.3.7") return "KeyWrap.RC2";
   if(oid_str == "1.2.840.113549.1.9.16.3.8") return "Compression.Zlib";
   if(oid_str == "1.2.840.113549.1.9.2") return "PKCS9.UnstructuredName";
   if(oid_str == "1.2.840.113549.1.9.3") return "PKCS9.ContentType";
   if(oid_str == "1.2.840.113549.1.9.4") return "PKCS9.MessageDigest";
   if(oid_str == "1.2.840.113549.1.9.7") return "PKCS9.ChallengePassword";
   if(oid_str == "1.2.840.113549.2.10") return "HMAC(SHA-384)";
   if(oid_str == "1.2.840.113549.2.11") return "HMAC(SHA-512)";
   if(oid_str == "1.2.840.113549.2.5") return "MD5";
   if(oid_str == "1.2.840.113549.2.7") return "HMAC(SHA-160)";
   if(oid_str == "1.2.840.113549.2.8") return "HMAC(SHA-224)";
   if(oid_str == "1.2.840.113549.2.9") return "HMAC(SHA-256)";
   if(oid_str == "1.2.840.113549.3.2") return "RC2/CBC";
   if(oid_str == "1.2.840.113549.3.7") return "TripleDES/CBC";
   if(oid_str == "1.3.101.110") return "Curve25519";
   if(oid_str == "1.3.101.112") return "Ed25519";
   if(oid_str == "1.3.132.0.10") return "secp256k1";
   if(oid_str == "1.3.132.0.30") return "secp160r2";
   if(oid_str == "1.3.132.0.31") return "secp192k1";
   if(oid_str == "1.3.132.0.32") return "secp224k1";
   if(oid_str == "1.3.132.0.33") return "secp224r1";
   if(oid_str == "1.3.132.0.34") return "secp384r1";
   if(oid_str == "1.3.132.0.35") return "secp521r1";
   if(oid_str == "1.3.132.0.8") return "secp160r1";
   if(oid_str == "1.3.132.0.9") return "secp160k1";
   if(oid_str == "1.3.132.1.12") return "ECDH";
   if(oid_str == "1.3.14.3.2.26") return "SHA-160";
   if(oid_str == "1.3.14.3.2.7") return "DES/CBC";
   if(oid_str == "1.3.36.3.2.1") return "RIPEMD-160";
   if(oid_str == "1.3.36.3.3.1.2") return "RSA/EMSA3(RIPEMD-160)";
   if(oid_str == "1.3.36.3.3.2.5.2.1") return "ECGDSA";
   if(oid_str == "1.3.36.3.3.2.5.4.1") return "ECGDSA/EMSA1(RIPEMD-160)";
   if(oid_str == "1.3.36.3.3.2.5.4.2") return "ECGDSA/EMSA1(SHA-160)";
   if(oid_str == "1.3.36.3.3.2.5.4.3") return "ECGDSA/EMSA1(SHA-224)";
   if(oid_str == "1.3.36.3.3.2.5.4.4") return "ECGDSA/EMSA1(SHA-256)";
   if(oid_str == "1.3.36.3.3.2.5.4.5") return "ECGDSA/EMSA1(SHA-384)";
   if(oid_str == "1.3.36.3.3.2.5.4.6") return "ECGDSA/EMSA1(SHA-512)";
   if(oid_str == "1.3.36.3.3.2.8.1.1.1") return "brainpool160r1";
   if(oid_str == "1.3.36.3.3.2.8.1.1.11") return "brainpool384r1";
   if(oid_str == "1.3.36.3.3.2.8.1.1.13") return "brainpool512r1";
   if(oid_str == "1.3.36.3.3.2.8.1.1.3") return "brainpool192r1";
   if(oid_str == "1.3.36.3.3.2.8.1.1.5") return "brainpool224r1";
   if(oid_str == "1.3.36.3.3.2.8.1.1.7") return "brainpool256r1";
   if(oid_str == "1.3.36.3.3.2.8.1.1.9") return "brainpool320r1";
   if(oid_str == "1.3.6.1.4.1.11591.12.2") return "Tiger(24,3)";
   if(oid_str == "1.3.6.1.4.1.25258.1.3") return "McEliece";
   if(oid_str == "1.3.6.1.4.1.25258.1.5") return "XMSS";
   if(oid_str == "1.3.6.1.4.1.25258.1.6.1") return "GOST-34.10/EMSA1(SHA-256)";
   if(oid_str == "1.3.6.1.4.1.25258.3.1") return "Serpent/CBC";
   if(oid_str == "1.3.6.1.4.1.25258.3.101") return "Serpent/GCM";
   if(oid_str == "1.3.6.1.4.1.25258.3.102") return "Twofish/GCM";
   if(oid_str == "1.3.6.1.4.1.25258.3.2") return "Threefish-512/CBC";
   if(oid_str == "1.3.6.1.4.1.25258.3.2.1") return "AES-128/OCB";
   if(oid_str == "1.3.6.1.4.1.25258.3.2.2") return "AES-192/OCB";
   if(oid_str == "1.3.6.1.4.1.25258.3.2.3") return "AES-256/OCB";
   if(oid_str == "1.3.6.1.4.1.25258.3.2.4") return "Serpent/OCB";
   if(oid_str == "1.3.6.1.4.1.25258.3.2.5") return "Twofish/OCB";
   if(oid_str == "1.3.6.1.4.1.25258.3.3") return "Twofish/CBC";
   if(oid_str == "1.3.6.1.4.1.3029.1.2.1") return "ElGamal";
   if(oid_str == "1.3.6.1.4.1.311.20.2.2") return "Microsoft SmartcardLogon";
   if(oid_str == "1.3.6.1.4.1.8301.3.1.2.9.0.38") return "secp521r1";
   if(oid_str == "1.3.6.1.5.5.7.1.1") return "PKIX.AuthorityInformationAccess";
   if(oid_str == "1.3.6.1.5.5.7.3.1") return "PKIX.ServerAuth";
   if(oid_str == "1.3.6.1.5.5.7.3.2") return "PKIX.ClientAuth";
   if(oid_str == "1.3.6.1.5.5.7.3.3") return "PKIX.CodeSigning";
   if(oid_str == "1.3.6.1.5.5.7.3.4") return "PKIX.EmailProtection";
   if(oid_str == "1.3.6.1.5.5.7.3.5") return "PKIX.IPsecEndSystem";
   if(oid_str == "1.3.6.1.5.5.7.3.6") return "PKIX.IPsecTunnel";
   if(oid_str == "1.3.6.1.5.5.7.3.7") return "PKIX.IPsecUser";
   if(oid_str == "1.3.6.1.5.5.7.3.8") return "PKIX.TimeStamping";
   if(oid_str == "1.3.6.1.5.5.7.3.9") return "PKIX.OCSPSigning";
   if(oid_str == "1.3.6.1.5.5.7.48.1") return "PKIX.OCSP";
   if(oid_str == "1.3.6.1.5.5.7.48.1.1") return "PKIX.OCSP.BasicResponse";
   if(oid_str == "1.3.6.1.5.5.7.8.5") return "PKIX.XMPPAddr";
   if(oid_str == "2.16.840.1.101.3.4.1.2") return "AES-128/CBC";
   if(oid_str == "2.16.840.1.101.3.4.1.22") return "AES-192/CBC";
   if(oid_str == "2.16.840.1.101.3.4.1.25") return "KeyWrap.AES-192";
   if(oid_str == "2.16.840.1.101.3.4.1.26") return "AES-192/GCM";
   if(oid_str == "2.16.840.1.101.3.4.1.27") return "AES-192/CCM";
   if(oid_str == "2.16.840.1.101.3.4.1.42") return "AES-256/CBC";
   if(oid_str == "2.16.840.1.101.3.4.1.45") return "KeyWrap.AES-256";
   if(oid_str == "2.16.840.1.101.3.4.1.46") return "AES-256/GCM";
   if(oid_str == "2.16.840.1.101.3.4.1.47") return "AES-256/CCM";
   if(oid_str == "2.16.840.1.101.3.4.1.5") return "KeyWrap.AES-128";
   if(oid_str == "2.16.840.1.101.3.4.1.6") return "AES-128/GCM";
   if(oid_str == "2.16.840.1.101.3.4.1.7") return "AES-128/CCM";
   if(oid_str == "2.16.840.1.101.3.4.2.1") return "SHA-256";
   if(oid_str == "2.16.840.1.101.3.4.2.10") return "SHA-3(512)";
   if(oid_str == "2.16.840.1.101.3.4.2.11") return "SHAKE-128";
   if(oid_str == "2.16.840.1.101.3.4.2.12") return "SHAKE-256";
   if(oid_str == "2.16.840.1.101.3.4.2.2") return "SHA-384";
   if(oid_str == "2.16.840.1.101.3.4.2.3") return "SHA-512";
   if(oid_str == "2.16.840.1.101.3.4.2.4") return "SHA-224";
   if(oid_str == "2.16.840.1.101.3.4.2.6") return "SHA-512-256";
   if(oid_str == "2.16.840.1.101.3.4.2.7") return "SHA-3(224)";
   if(oid_str == "2.16.840.1.101.3.4.2.8") return "SHA-3(256)";
   if(oid_str == "2.16.840.1.101.3.4.2.9") return "SHA-3(384)";
   if(oid_str == "2.16.840.1.101.3.4.3.1") return "DSA/EMSA1(SHA-224)";
   if(oid_str == "2.16.840.1.101.3.4.3.10") return "ECDSA/EMSA1(SHA-3(256))";
   if(oid_str == "2.16.840.1.101.3.4.3.11") return "ECDSA/EMSA1(SHA-3(384))";
   if(oid_str == "2.16.840.1.101.3.4.3.12") return "ECDSA/EMSA1(SHA-3(512))";
   if(oid_str == "2.16.840.1.101.3.4.3.13") return "RSA/EMSA3(SHA-3(224))";
   if(oid_str == "2.16.840.1.101.3.4.3.14") return "RSA/EMSA3(SHA-3(256))";
   if(oid_str == "2.16.840.1.101.3.4.3.15") return "RSA/EMSA3(SHA-3(384))";
   if(oid_str == "2.16.840.1.101.3.4.3.16") return "RSA/EMSA3(SHA-3(512))";
   if(oid_str == "2.16.840.1.101.3.4.3.2") return "DSA/EMSA1(SHA-256)";
   if(oid_str == "2.16.840.1.101.3.4.3.3") return "DSA/EMSA1(SHA-384)";
   if(oid_str == "2.16.840.1.101.3.4.3.4") return "DSA/EMSA1(SHA-512)";
   if(oid_str == "2.16.840.1.101.3.4.3.5") return "DSA/EMSA1(SHA-3(224))";
   if(oid_str == "2.16.840.1.101.3.4.3.6") return "DSA/EMSA1(SHA-3(256))";
   if(oid_str == "2.16.840.1.101.3.4.3.7") return "DSA/EMSA1(SHA-3(384))";
   if(oid_str == "2.16.840.1.101.3.4.3.8") return "DSA/EMSA1(SHA-3(512))";
   if(oid_str == "2.16.840.1.101.3.4.3.9") return "ECDSA/EMSA1(SHA-3(224))";
   if(oid_str == "2.5.29.14") return "X509v3.SubjectKeyIdentifier";
   if(oid_str == "2.5.29.15") return "X509v3.KeyUsage";
   if(oid_str == "2.5.29.17") return "X509v3.SubjectAlternativeName";
   if(oid_str == "2.5.29.18") return "X509v3.IssuerAlternativeName";
   if(oid_str == "2.5.29.19") return "X509v3.BasicConstraints";
   if(oid_str == "2.5.29.20") return "X509v3.CRLNumber";
   if(oid_str == "2.5.29.21") return "X509v3.ReasonCode";
   if(oid_str == "2.5.29.23") return "X509v3.HoldInstructionCode";
   if(oid_str == "2.5.29.24") return "X509v3.InvalidityDate";
   if(oid_str == "2.5.29.30") return "X509v3.NameConstraints";
   if(oid_str == "2.5.29.31") return "X509v3.CRLDistributionPoints";
   if(oid_str == "2.5.29.32") return "X509v3.CertificatePolicies";
   if(oid_str == "2.5.29.32.0") return "X509v3.AnyPolicy";
   if(oid_str == "2.5.29.35") return "X509v3.AuthorityKeyIdentifier";
   if(oid_str == "2.5.29.36") return "X509v3.PolicyConstraints";
   if(oid_str == "2.5.29.37") return "X509v3.ExtendedKeyUsage";
   if(oid_str == "2.5.4.10") return "X520.Organization";
   if(oid_str == "2.5.4.11") return "X520.OrganizationalUnit";
   if(oid_str == "2.5.4.12") return "X520.Title";
   if(oid_str == "2.5.4.3") return "X520.CommonName";
   if(oid_str == "2.5.4.4") return "X520.Surname";
   if(oid_str == "2.5.4.42") return "X520.GivenName";
   if(oid_str == "2.5.4.43") return "X520.Initials";
   if(oid_str == "2.5.4.44") return "X520.GenerationalQualifier";
   if(oid_str == "2.5.4.46") return "X520.DNQualifier";
   if(oid_str == "2.5.4.5") return "X520.SerialNumber";
   if(oid_str == "2.5.4.6") return "X520.Country";
   if(oid_str == "2.5.4.65") return "X520.Pseudonym";
   if(oid_str == "2.5.4.7") return "X520.Locality";
   if(oid_str == "2.5.4.8") return "X520.State";
   if(oid_str == "2.5.8.1.1") return "RSA";

#if defined(BOTAN_HOUSE_ECC_CURVE_NAME)
   if(oid_str == BOTAN_HOUSE_ECC_CURVE_OID) return BOTAN_HOUSE_ECC_CURVE_NAME;
#endif

   return std::string();
   }

OID lookup(const std::string& name)
   {
   if(name == "AES-128/CBC") return OID("2.16.840.1.101.3.4.1.2");
   if(name == "AES-128/CCM") return OID("2.16.840.1.101.3.4.1.7");
   if(name == "AES-128/GCM") return OID("2.16.840.1.101.3.4.1.6");
   if(name == "AES-128/OCB") return OID("1.3.6.1.4.1.25258.3.2.1");
   if(name == "AES-192/CBC") return OID("2.16.840.1.101.3.4.1.22");
   if(name == "AES-192/CCM") return OID("2.16.840.1.101.3.4.1.27");
   if(name == "AES-192/GCM") return OID("2.16.840.1.101.3.4.1.26");
   if(name == "AES-192/OCB") return OID("1.3.6.1.4.1.25258.3.2.2");
   if(name == "AES-256/CBC") return OID("2.16.840.1.101.3.4.1.42");
   if(name == "AES-256/CCM") return OID("2.16.840.1.101.3.4.1.47");
   if(name == "AES-256/GCM") return OID("2.16.840.1.101.3.4.1.46");
   if(name == "AES-256/OCB") return OID("1.3.6.1.4.1.25258.3.2.3");
   if(name == "CAST-128/CBC") return OID("1.2.840.113533.7.66.10");
   if(name == "Compression.Zlib") return OID("1.2.840.113549.1.9.16.3.8");
   if(name == "Curve25519") return OID("1.3.101.110");
   if(name == "DES/CBC") return OID("1.3.14.3.2.7");
   if(name == "DH") return OID("1.2.840.10046.2.1");
   if(name == "DSA") return OID("1.2.840.10040.4.1");
   if(name == "DSA/EMSA1(SHA-160)") return OID("1.2.840.10040.4.3");
   if(name == "DSA/EMSA1(SHA-224)") return OID("2.16.840.1.101.3.4.3.1");
   if(name == "DSA/EMSA1(SHA-256)") return OID("2.16.840.1.101.3.4.3.2");
   if(name == "DSA/EMSA1(SHA-3(224))") return OID("2.16.840.1.101.3.4.3.5");
   if(name == "DSA/EMSA1(SHA-3(256))") return OID("2.16.840.1.101.3.4.3.6");
   if(name == "DSA/EMSA1(SHA-3(384))") return OID("2.16.840.1.101.3.4.3.7");
   if(name == "DSA/EMSA1(SHA-3(512))") return OID("2.16.840.1.101.3.4.3.8");
   if(name == "DSA/EMSA1(SHA-384)") return OID("2.16.840.1.101.3.4.3.3");
   if(name == "DSA/EMSA1(SHA-512)") return OID("2.16.840.1.101.3.4.3.4");
   if(name == "ECDH") return OID("1.3.132.1.12");
   if(name == "ECDSA") return OID("1.2.840.10045.2.1");
   if(name == "ECDSA/EMSA1(SHA-160)") return OID("1.2.840.10045.4.1");
   if(name == "ECDSA/EMSA1(SHA-224)") return OID("1.2.840.10045.4.3.1");
   if(name == "ECDSA/EMSA1(SHA-256)") return OID("1.2.840.10045.4.3.2");
   if(name == "ECDSA/EMSA1(SHA-3(224))") return OID("2.16.840.1.101.3.4.3.9");
   if(name == "ECDSA/EMSA1(SHA-3(256))") return OID("2.16.840.1.101.3.4.3.10");
   if(name == "ECDSA/EMSA1(SHA-3(384))") return OID("2.16.840.1.101.3.4.3.11");
   if(name == "ECDSA/EMSA1(SHA-3(512))") return OID("2.16.840.1.101.3.4.3.12");
   if(name == "ECDSA/EMSA1(SHA-384)") return OID("1.2.840.10045.4.3.3");
   if(name == "ECDSA/EMSA1(SHA-512)") return OID("1.2.840.10045.4.3.4");
   if(name == "ECGDSA") return OID("1.3.36.3.3.2.5.2.1");
   if(name == "ECGDSA/EMSA1(RIPEMD-160)") return OID("1.3.36.3.3.2.5.4.1");
   if(name == "ECGDSA/EMSA1(SHA-160)") return OID("1.3.36.3.3.2.5.4.2");
   if(name == "ECGDSA/EMSA1(SHA-224)") return OID("1.3.36.3.3.2.5.4.3");
   if(name == "ECGDSA/EMSA1(SHA-256)") return OID("1.3.36.3.3.2.5.4.4");
   if(name == "ECGDSA/EMSA1(SHA-384)") return OID("1.3.36.3.3.2.5.4.5");
   if(name == "ECGDSA/EMSA1(SHA-512)") return OID("1.3.36.3.3.2.5.4.6");
   if(name == "ECKCDSA") return OID("1.0.14888.3.0.5");
   if(name == "ECKCDSA/EMSA1(SHA-1)") return OID("1.2.410.200004.1.100.4.3");
   if(name == "ECKCDSA/EMSA1(SHA-224)") return OID("1.2.410.200004.1.100.4.4");
   if(name == "ECKCDSA/EMSA1(SHA-256)") return OID("1.2.410.200004.1.100.4.5");
   if(name == "Ed25519") return OID("1.3.101.112");
   if(name == "ElGamal") return OID("1.3.6.1.4.1.3029.1.2.1");
   if(name == "GOST-34.10") return OID("1.2.643.2.2.19");
   if(name == "GOST-34.10/EMSA1(GOST-R-34.11-94)") return OID("1.2.643.2.2.3");
   if(name == "GOST-34.10/EMSA1(SHA-256)") return OID("1.3.6.1.4.1.25258.1.6.1");
   if(name == "HMAC(SHA-160)") return OID("1.2.840.113549.2.7");
   if(name == "HMAC(SHA-224)") return OID("1.2.840.113549.2.8");
   if(name == "HMAC(SHA-256)") return OID("1.2.840.113549.2.9");
   if(name == "HMAC(SHA-384)") return OID("1.2.840.113549.2.10");
   if(name == "HMAC(SHA-512)") return OID("1.2.840.113549.2.11");
   if(name == "KeyWrap.AES-128") return OID("2.16.840.1.101.3.4.1.5");
   if(name == "KeyWrap.AES-192") return OID("2.16.840.1.101.3.4.1.25");
   if(name == "KeyWrap.AES-256") return OID("2.16.840.1.101.3.4.1.45");
   if(name == "KeyWrap.CAST-128") return OID("1.2.840.113533.7.66.15");
   if(name == "KeyWrap.RC2") return OID("1.2.840.113549.1.9.16.3.7");
   if(name == "KeyWrap.TripleDES") return OID("1.2.840.113549.1.9.16.3.6");
   if(name == "MD5") return OID("1.2.840.113549.2.5");
   if(name == "MGF1") return OID("1.2.840.113549.1.1.8");
   if(name == "McEliece") return OID("1.3.6.1.4.1.25258.1.3");
   if(name == "Microsoft SmartcardLogon") return OID("1.3.6.1.4.1.311.20.2.2");
   if(name == "PBE-PKCS5v20") return OID("1.2.840.113549.1.5.13");
   if(name == "PKCS5.PBKDF2") return OID("1.2.840.113549.1.5.12");
   if(name == "PKCS9.ChallengePassword") return OID("1.2.840.113549.1.9.7");
   if(name == "PKCS9.ContentType") return OID("1.2.840.113549.1.9.3");
   if(name == "PKCS9.EmailAddress") return OID("1.2.840.113549.1.9.1");
   if(name == "PKCS9.ExtensionRequest") return OID("1.2.840.113549.1.9.14");
   if(name == "PKCS9.MessageDigest") return OID("1.2.840.113549.1.9.4");
   if(name == "PKCS9.UnstructuredName") return OID("1.2.840.113549.1.9.2");
   if(name == "PKIX.AuthorityInformationAccess") return OID("1.3.6.1.5.5.7.1.1");
   if(name == "PKIX.ClientAuth") return OID("1.3.6.1.5.5.7.3.2");
   if(name == "PKIX.CodeSigning") return OID("1.3.6.1.5.5.7.3.3");
   if(name == "PKIX.EmailProtection") return OID("1.3.6.1.5.5.7.3.4");
   if(name == "PKIX.IPsecEndSystem") return OID("1.3.6.1.5.5.7.3.5");
   if(name == "PKIX.IPsecTunnel") return OID("1.3.6.1.5.5.7.3.6");
   if(name == "PKIX.IPsecUser") return OID("1.3.6.1.5.5.7.3.7");
   if(name == "PKIX.OCSP") return OID("1.3.6.1.5.5.7.48.1");
   if(name == "PKIX.OCSP.BasicResponse") return OID("1.3.6.1.5.5.7.48.1.1");
   if(name == "PKIX.OCSPSigning") return OID("1.3.6.1.5.5.7.3.9");
   if(name == "PKIX.ServerAuth") return OID("1.3.6.1.5.5.7.3.1");
   if(name == "PKIX.TimeStamping") return OID("1.3.6.1.5.5.7.3.8");
   if(name == "PKIX.XMPPAddr") return OID("1.3.6.1.5.5.7.8.5");
   if(name == "RC2/CBC") return OID("1.2.840.113549.3.2");
   if(name == "RIPEMD-160") return OID("1.3.36.3.2.1");
   if(name == "RSA") return OID("1.2.840.113549.1.1.1");
   if(name == "RSA/EMSA3(MD5)") return OID("1.2.840.113549.1.1.4");
   if(name == "RSA/EMSA3(RIPEMD-160)") return OID("1.3.36.3.3.1.2");
   if(name == "RSA/EMSA3(SHA-160)") return OID("1.2.840.113549.1.1.5");
   if(name == "RSA/EMSA3(SHA-224)") return OID("1.2.840.113549.1.1.14");
   if(name == "RSA/EMSA3(SHA-256)") return OID("1.2.840.113549.1.1.11");
   if(name == "RSA/EMSA3(SHA-3(224))") return OID("2.16.840.1.101.3.4.3.13");
   if(name == "RSA/EMSA3(SHA-3(256))") return OID("2.16.840.1.101.3.4.3.14");
   if(name == "RSA/EMSA3(SHA-3(384))") return OID("2.16.840.1.101.3.4.3.15");
   if(name == "RSA/EMSA3(SHA-3(512))") return OID("2.16.840.1.101.3.4.3.16");
   if(name == "RSA/EMSA3(SHA-384)") return OID("1.2.840.113549.1.1.12");
   if(name == "RSA/EMSA3(SHA-512)") return OID("1.2.840.113549.1.1.13");
   if(name == "RSA/EMSA3(SHA-512-256)") return OID("1.2.840.113549.1.1.16");
   if(name == "RSA/EMSA3(SM3)") return OID("1.2.156.10197.1.504");
   if(name == "RSA/EMSA4") return OID("1.2.840.113549.1.1.10");
   if(name == "RSA/OAEP") return OID("1.2.840.113549.1.1.7");
   if(name == "SEED/CBC") return OID("1.2.410.200004.1.4");
   if(name == "SHA-160") return OID("1.3.14.3.2.26");
   if(name == "SHA-224") return OID("2.16.840.1.101.3.4.2.4");
   if(name == "SHA-256") return OID("2.16.840.1.101.3.4.2.1");
   if(name == "SHA-3(224)") return OID("2.16.840.1.101.3.4.2.7");
   if(name == "SHA-3(256)") return OID("2.16.840.1.101.3.4.2.8");
   if(name == "SHA-3(384)") return OID("2.16.840.1.101.3.4.2.9");
   if(name == "SHA-3(512)") return OID("2.16.840.1.101.3.4.2.10");
   if(name == "SHA-384") return OID("2.16.840.1.101.3.4.2.2");
   if(name == "SHA-512") return OID("2.16.840.1.101.3.4.2.3");
   if(name == "SHA-512-256") return OID("2.16.840.1.101.3.4.2.6");
   if(name == "SHAKE-128") return OID("2.16.840.1.101.3.4.2.11");
   if(name == "SHAKE-256") return OID("2.16.840.1.101.3.4.2.12");
   if(name == "SM2_Enc") return OID("1.2.156.10197.1.301.3");
   if(name == "SM2_Kex") return OID("1.2.156.10197.1.301.2");
   if(name == "SM2_Sig") return OID("1.2.156.10197.1.301.1");
   if(name == "SM3") return OID("1.2.156.10197.1.401");
   if(name == "Serpent/CBC") return OID("1.3.6.1.4.1.25258.3.1");
   if(name == "Serpent/GCM") return OID("1.3.6.1.4.1.25258.3.101");
   if(name == "Serpent/OCB") return OID("1.3.6.1.4.1.25258.3.2.4");
   if(name == "Streebog-256") return OID("1.2.643.7.1.1.2.2");
   if(name == "Streebog-512") return OID("1.2.643.7.1.1.2.3");
   if(name == "Threefish-512/CBC") return OID("1.3.6.1.4.1.25258.3.2");
   if(name == "Tiger(24,3)") return OID("1.3.6.1.4.1.11591.12.2");
   if(name == "TripleDES/CBC") return OID("1.2.840.113549.3.7");
   if(name == "Twofish/CBC") return OID("1.3.6.1.4.1.25258.3.3");
   if(name == "Twofish/GCM") return OID("1.3.6.1.4.1.25258.3.102");
   if(name == "Twofish/OCB") return OID("1.3.6.1.4.1.25258.3.2.5");
   if(name == "X509v3.AnyPolicy") return OID("2.5.29.32.0");
   if(name == "X509v3.AuthorityKeyIdentifier") return OID("2.5.29.35");
   if(name == "X509v3.BasicConstraints") return OID("2.5.29.19");
   if(name == "X509v3.CRLDistributionPoints") return OID("2.5.29.31");
   if(name == "X509v3.CRLNumber") return OID("2.5.29.20");
   if(name == "X509v3.CertificatePolicies") return OID("2.5.29.32");
   if(name == "X509v3.ExtendedKeyUsage") return OID("2.5.29.37");
   if(name == "X509v3.HoldInstructionCode") return OID("2.5.29.23");
   if(name == "X509v3.InvalidityDate") return OID("2.5.29.24");
   if(name == "X509v3.IssuerAlternativeName") return OID("2.5.29.18");
   if(name == "X509v3.KeyUsage") return OID("2.5.29.15");
   if(name == "X509v3.NameConstraints") return OID("2.5.29.30");
   if(name == "X509v3.PolicyConstraints") return OID("2.5.29.36");
   if(name == "X509v3.ReasonCode") return OID("2.5.29.21");
   if(name == "X509v3.SubjectAlternativeName") return OID("2.5.29.17");
   if(name == "X509v3.SubjectKeyIdentifier") return OID("2.5.29.14");
   if(name == "X520.CommonName") return OID("2.5.4.3");
   if(name == "X520.Country") return OID("2.5.4.6");
   if(name == "X520.DNQualifier") return OID("2.5.4.46");
   if(name == "X520.GenerationalQualifier") return OID("2.5.4.44");
   if(name == "X520.GivenName") return OID("2.5.4.42");
   if(name == "X520.Initials") return OID("2.5.4.43");
   if(name == "X520.Locality") return OID("2.5.4.7");
   if(name == "X520.Organization") return OID("2.5.4.10");
   if(name == "X520.OrganizationalUnit") return OID("2.5.4.11");
   if(name == "X520.Pseudonym") return OID("2.5.4.65");
   if(name == "X520.SerialNumber") return OID("2.5.4.5");
   if(name == "X520.State") return OID("2.5.4.8");
   if(name == "X520.Surname") return OID("2.5.4.4");
   if(name == "X520.Title") return OID("2.5.4.12");
   if(name == "XMSS") return OID("1.3.6.1.4.1.25258.1.5");
   if(name == "brainpool160r1") return OID("1.3.36.3.3.2.8.1.1.1");
   if(name == "brainpool192r1") return OID("1.3.36.3.3.2.8.1.1.3");
   if(name == "brainpool224r1") return OID("1.3.36.3.3.2.8.1.1.5");
   if(name == "brainpool256r1") return OID("1.3.36.3.3.2.8.1.1.7");
   if(name == "brainpool320r1") return OID("1.3.36.3.3.2.8.1.1.9");
   if(name == "brainpool384r1") return OID("1.3.36.3.3.2.8.1.1.11");
   if(name == "brainpool512r1") return OID("1.3.36.3.3.2.8.1.1.13");
   if(name == "frp256v1") return OID("1.2.250.1.223.101.256.1");
   if(name == "gost_256A") return OID("1.2.643.2.2.35.1");
   if(name == "secp160k1") return OID("1.3.132.0.9");
   if(name == "secp160r1") return OID("1.3.132.0.8");
   if(name == "secp160r2") return OID("1.3.132.0.30");
   if(name == "secp192k1") return OID("1.3.132.0.31");
   if(name == "secp192r1") return OID("1.2.840.10045.3.1.1");
   if(name == "secp224k1") return OID("1.3.132.0.32");
   if(name == "secp224r1") return OID("1.3.132.0.33");
   if(name == "secp256k1") return OID("1.3.132.0.10");
   if(name == "secp256r1") return OID("1.2.840.10045.3.1.7");
   if(name == "secp384r1") return OID("1.3.132.0.34");
   if(name == "secp521r1") return OID("1.3.132.0.35");
   if(name == "sm2p256v1") return OID("1.2.156.10197.1.301");
   if(name == "x962_p192v2") return OID("1.2.840.10045.3.1.2");
   if(name == "x962_p192v3") return OID("1.2.840.10045.3.1.3");
   if(name == "x962_p239v1") return OID("1.2.840.10045.3.1.4");
   if(name == "x962_p239v2") return OID("1.2.840.10045.3.1.5");
   if(name == "x962_p239v3") return OID("1.2.840.10045.3.1.6");

#if defined(BOTAN_HOUSE_ECC_CURVE_NAME)
   if(name == BOTAN_HOUSE_ECC_CURVE_NAME) return OID(BOTAN_HOUSE_ECC_CURVE_OID);
#endif

   return OID();
   }

}

}

/*
* SCAN Name Abstraction
* (C) 2008-2009,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

std::string make_arg(
   const std::vector<std::pair<size_t, std::string> >& name, size_t start)
   {
   std::string output = name[start].second;
   size_t level = name[start].first;

   size_t paren_depth = 0;

   for(size_t i = start + 1; i != name.size(); ++i)
      {
      if(name[i].first <= name[start].first)
         break;

      if(name[i].first > level)
         {
         output += "(" + name[i].second;
         ++paren_depth;
         }
      else if(name[i].first < level)
         {
         output += ")," + name[i].second;
         --paren_depth;
         }
      else
         {
         if(output[output.size() - 1] != '(')
            output += ",";
         output += name[i].second;
         }

      level = name[i].first;
      }

   for(size_t i = 0; i != paren_depth; ++i)
      output += ")";

   return output;
   }

}

SCAN_Name::SCAN_Name(const char* algo_spec) : SCAN_Name(std::string(algo_spec))
   {
   }

SCAN_Name::SCAN_Name(std::string algo_spec) : m_orig_algo_spec(algo_spec), m_alg_name(), m_args(), m_mode_info()
   {
   std::vector<std::pair<size_t, std::string> > name;
   size_t level = 0;
   std::pair<size_t, std::string> accum = std::make_pair(level, "");

   const std::string decoding_error = "Bad SCAN name '" + algo_spec + "': ";

   for(size_t i = 0; i != algo_spec.size(); ++i)
      {
      char c = algo_spec[i];

      if(c == '/' || c == ',' || c == '(' || c == ')')
         {
         if(c == '(')
            ++level;
         else if(c == ')')
            {
            if(level == 0)
               throw Decoding_Error(decoding_error + "Mismatched parens");
            --level;
            }

         if(c == '/' && level > 0)
            accum.second.push_back(c);
         else
            {
            if(accum.second != "")
               name.push_back(accum);
            accum = std::make_pair(level, "");
            }
         }
      else
         accum.second.push_back(c);
      }

   if(accum.second != "")
      name.push_back(accum);

   if(level != 0)
      throw Decoding_Error(decoding_error + "Missing close paren");

   if(name.size() == 0)
      throw Decoding_Error(decoding_error + "Empty name");

   m_alg_name = name[0].second;

   bool in_modes = false;

   for(size_t i = 1; i != name.size(); ++i)
      {
      if(name[i].first == 0)
         {
         m_mode_info.push_back(make_arg(name, i));
         in_modes = true;
         }
      else if(name[i].first == 1 && !in_modes)
         m_args.push_back(make_arg(name, i));
      }
   }

std::string SCAN_Name::arg(size_t i) const
   {
   if(i >= arg_count())
      throw Invalid_Argument("SCAN_Name::arg " + std::to_string(i) +
                             " out of range for '" + as_string() + "'");
   return m_args[i];
   }

std::string SCAN_Name::arg(size_t i, const std::string& def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return m_args[i];
   }

size_t SCAN_Name::arg_as_integer(size_t i, size_t def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return to_u32bit(m_args[i]);
   }

}
/*
* OctetString
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Create an OctetString from RNG output
*/
OctetString::OctetString(RandomNumberGenerator& rng,
                         size_t len)
   {
   m_data = rng.random_vec(len);
   }

/*
* Create an OctetString from a hex string
*/
OctetString::OctetString(const std::string& hex_string)
   {
   m_data.resize(1 + hex_string.length() / 2);
   m_data.resize(hex_decode(m_data.data(), hex_string));
   }

/*
* Create an OctetString from a byte string
*/
OctetString::OctetString(const uint8_t in[], size_t n)
   {
   m_data.assign(in, in + n);
   }

/*
* Set the parity of each key byte to odd
*/
void OctetString::set_odd_parity()
   {
   const uint8_t ODD_PARITY[256] = {
      0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07, 0x08, 0x08, 0x0B, 0x0B,
      0x0D, 0x0D, 0x0E, 0x0E, 0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16,
      0x19, 0x19, 0x1A, 0x1A, 0x1C, 0x1C, 0x1F, 0x1F, 0x20, 0x20, 0x23, 0x23,
      0x25, 0x25, 0x26, 0x26, 0x29, 0x29, 0x2A, 0x2A, 0x2C, 0x2C, 0x2F, 0x2F,
      0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37, 0x38, 0x38, 0x3B, 0x3B,
      0x3D, 0x3D, 0x3E, 0x3E, 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46,
      0x49, 0x49, 0x4A, 0x4A, 0x4C, 0x4C, 0x4F, 0x4F, 0x51, 0x51, 0x52, 0x52,
      0x54, 0x54, 0x57, 0x57, 0x58, 0x58, 0x5B, 0x5B, 0x5D, 0x5D, 0x5E, 0x5E,
      0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67, 0x68, 0x68, 0x6B, 0x6B,
      0x6D, 0x6D, 0x6E, 0x6E, 0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76,
      0x79, 0x79, 0x7A, 0x7A, 0x7C, 0x7C, 0x7F, 0x7F, 0x80, 0x80, 0x83, 0x83,
      0x85, 0x85, 0x86, 0x86, 0x89, 0x89, 0x8A, 0x8A, 0x8C, 0x8C, 0x8F, 0x8F,
      0x91, 0x91, 0x92, 0x92, 0x94, 0x94, 0x97, 0x97, 0x98, 0x98, 0x9B, 0x9B,
      0x9D, 0x9D, 0x9E, 0x9E, 0xA1, 0xA1, 0xA2, 0xA2, 0xA4, 0xA4, 0xA7, 0xA7,
      0xA8, 0xA8, 0xAB, 0xAB, 0xAD, 0xAD, 0xAE, 0xAE, 0xB0, 0xB0, 0xB3, 0xB3,
      0xB5, 0xB5, 0xB6, 0xB6, 0xB9, 0xB9, 0xBA, 0xBA, 0xBC, 0xBC, 0xBF, 0xBF,
      0xC1, 0xC1, 0xC2, 0xC2, 0xC4, 0xC4, 0xC7, 0xC7, 0xC8, 0xC8, 0xCB, 0xCB,
      0xCD, 0xCD, 0xCE, 0xCE, 0xD0, 0xD0, 0xD3, 0xD3, 0xD5, 0xD5, 0xD6, 0xD6,
      0xD9, 0xD9, 0xDA, 0xDA, 0xDC, 0xDC, 0xDF, 0xDF, 0xE0, 0xE0, 0xE3, 0xE3,
      0xE5, 0xE5, 0xE6, 0xE6, 0xE9, 0xE9, 0xEA, 0xEA, 0xEC, 0xEC, 0xEF, 0xEF,
      0xF1, 0xF1, 0xF2, 0xF2, 0xF4, 0xF4, 0xF7, 0xF7, 0xF8, 0xF8, 0xFB, 0xFB,
      0xFD, 0xFD, 0xFE, 0xFE };

   for(size_t j = 0; j != m_data.size(); ++j)
      m_data[j] = ODD_PARITY[m_data[j]];
   }

/*
* Hex encode an OctetString
*/
std::string OctetString::as_string() const
   {
   return hex_encode(m_data.data(), m_data.size());
   }

/*
* XOR Operation for OctetStrings
*/
OctetString& OctetString::operator^=(const OctetString& k)
   {
   if(&k == this) { zeroise(m_data); return (*this); }
   xor_buf(m_data.data(), k.begin(), std::min(length(), k.length()));
   return (*this);
   }

/*
* Equality Operation for OctetStrings
*/
bool operator==(const OctetString& s1, const OctetString& s2)
   {
   return (s1.bits_of() == s2.bits_of());
   }

/*
* Unequality Operation for OctetStrings
*/
bool operator!=(const OctetString& s1, const OctetString& s2)
   {
   return !(s1 == s2);
   }

/*
* Append Operation for OctetStrings
*/
OctetString operator+(const OctetString& k1, const OctetString& k2)
   {
   secure_vector<uint8_t> out;
   out += k1.bits_of();
   out += k2.bits_of();
   return OctetString(out);
   }

/*
* XOR Operation for OctetStrings
*/
OctetString operator^(const OctetString& k1, const OctetString& k2)
   {
   secure_vector<uint8_t> out(std::max(k1.length(), k2.length()));

   copy_mem(out.data(), k1.begin(), k1.length());
   xor_buf(out.data(), k2.begin(), k2.length());
   return OctetString(out);
   }

}
/*
* Base64 Encoding and Decoding
* (C) 2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

static const uint8_t BIN_TO_BASE64[64] = {
   'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
   'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
   'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
   'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
   '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

void do_base64_encode(char out[4], const uint8_t in[3])
   {
   out[0] = BIN_TO_BASE64[(in[0] & 0xFC) >> 2];
   out[1] = BIN_TO_BASE64[((in[0] & 0x03) << 4) | (in[1] >> 4)];
   out[2] = BIN_TO_BASE64[((in[1] & 0x0F) << 2) | (in[2] >> 6)];
   out[3] = BIN_TO_BASE64[in[2] & 0x3F];
   }

}

size_t base64_encode(char out[],
                     const uint8_t in[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs)
   {
   input_consumed = 0;

   size_t input_remaining = input_length;
   size_t output_produced = 0;

   while(input_remaining >= 3)
      {
      do_base64_encode(out + output_produced, in + input_consumed);

      input_consumed += 3;
      output_produced += 4;
      input_remaining -= 3;
      }

   if(final_inputs && input_remaining)
      {
      uint8_t remainder[3] = { 0 };
      for(size_t i = 0; i != input_remaining; ++i)
         remainder[i] = in[input_consumed + i];

      do_base64_encode(out + output_produced, remainder);

      size_t empty_bits = 8 * (3 - input_remaining);
      size_t index = output_produced + 4 - 1;
      while(empty_bits >= 8)
         {
         out[index--] = '=';
         empty_bits -= 6;
         }

      input_consumed += input_remaining;
      output_produced += 4;
      }

   return output_produced;
   }

std::string base64_encode(const uint8_t input[],
                          size_t input_length)
   {
   const size_t output_length = base64_encode_max_output(input_length);
   std::string output(output_length, 0);

   size_t consumed = 0;
   size_t produced = 0;
   
   if (output_length > 0)
   {
      produced = base64_encode(&output.front(),
                               input, input_length,
                               consumed, true);
   }

   BOTAN_ASSERT_EQUAL(consumed, input_length, "Consumed the entire input");
   BOTAN_ASSERT_EQUAL(produced, output.size(), "Produced expected size");

   return output;
   }

size_t base64_decode(uint8_t output[],
                     const char input[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs,
                     bool ignore_ws)
   {
   /*
   * Base64 Decoder Lookup Table
   * Warning: assumes ASCII encodings
   */
   static const uint8_t BASE64_TO_BIN[256] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
      0x80, 0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F, 0x34, 0x35,
      0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF,
      0xFF, 0x81, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04,
      0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
      0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
      0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1A, 0x1B, 0x1C,
      0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
      0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
      0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

   uint8_t* out_ptr = output;
   uint8_t decode_buf[4];
   size_t decode_buf_pos = 0;
   size_t final_truncate = 0;

   clear_mem(output, input_length * 3 / 4);

   for(size_t i = 0; i != input_length; ++i)
      {
      const uint8_t bin = BASE64_TO_BIN[static_cast<uint8_t>(input[i])];

      if(bin <= 0x3F)
         {
         decode_buf[decode_buf_pos] = bin;
         decode_buf_pos += 1;
         }
      else if(!(bin == 0x81 || (bin == 0x80 && ignore_ws)))
         {
         std::string bad_char(1, input[i]);
         if(bad_char == "\t")
           bad_char = "\\t";
         else if(bad_char == "\n")
           bad_char = "\\n";
         else if(bad_char == "\r")
           bad_char = "\\r";

         throw Invalid_Argument(
           std::string("base64_decode: invalid base64 character '") +
           bad_char + "'");
         }

      /*
      * If we're at the end of the input, pad with 0s and truncate
      */
      if(final_inputs && (i == input_length - 1))
         {
         if(decode_buf_pos)
            {
            for(size_t j = decode_buf_pos; j != 4; ++j)
               decode_buf[j] = 0;
            final_truncate = (4 - decode_buf_pos);
            decode_buf_pos = 4;
            }
         }

      if(decode_buf_pos == 4)
         {
         out_ptr[0] = (decode_buf[0] << 2) | (decode_buf[1] >> 4);
         out_ptr[1] = (decode_buf[1] << 4) | (decode_buf[2] >> 2);
         out_ptr[2] = (decode_buf[2] << 6) | decode_buf[3];

         out_ptr += 3;
         decode_buf_pos = 0;
         input_consumed = i+1;
         }
      }

   while(input_consumed < input_length &&
         BASE64_TO_BIN[static_cast<uint8_t>(input[input_consumed])] == 0x80)
      {
      ++input_consumed;
      }

   size_t written = (out_ptr - output) - final_truncate;

   return written;
   }

size_t base64_decode(uint8_t output[],
                     const char input[],
                     size_t input_length,
                     bool ignore_ws)
   {
   size_t consumed = 0;
   size_t written = base64_decode(output, input, input_length,
                                  consumed, true, ignore_ws);

   if(consumed != input_length)
      throw Invalid_Argument("base64_decode: input did not have full bytes");

   return written;
   }

size_t base64_decode(uint8_t output[],
                     const std::string& input,
                     bool ignore_ws)
   {
   return base64_decode(output, input.data(), input.length(), ignore_ws);
   }

secure_vector<uint8_t> base64_decode(const char input[],
                                 size_t input_length,
                                 bool ignore_ws)
   {
   const size_t output_length = base64_decode_max_output(input_length);
   secure_vector<uint8_t> bin(output_length);

   size_t written = base64_decode(bin.data(),
                                  input,
                                  input_length,
                                  ignore_ws);

   bin.resize(written);
   return bin;
   }

secure_vector<uint8_t> base64_decode(const std::string& input,
                                 bool ignore_ws)
   {
   return base64_decode(input.data(), input.size(), ignore_ws);
   }

size_t base64_encode_max_output(size_t input_length)
   {
   return (round_up(input_length, 3) / 3) * 4;
   }

size_t base64_decode_max_output(size_t input_length)
   {
   return (round_up(input_length, 4) * 3) / 4;
   }

}
/*
* BigInt Encoding/Decoding
* (C) 1999-2010,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Encode a BigInt
*/
void BigInt::encode(uint8_t output[], const BigInt& n, Base base)
   {
   if(base == Binary)
      {
      n.binary_encode(output);
      }
   else if(base == Hexadecimal)
      {
      secure_vector<uint8_t> binary(n.encoded_size(Binary));
      n.binary_encode(binary.data());

      hex_encode(cast_uint8_ptr_to_char(output),
                 binary.data(), binary.size());
      }
   else if(base == Decimal)
      {
      BigInt copy = n;
      BigInt remainder;
      copy.set_sign(Positive);
      const size_t output_size = n.encoded_size(Decimal);
      for(size_t j = 0; j != output_size; ++j)
         {
         divide(copy, 10, copy, remainder);
         output[output_size - 1 - j] =
            Charset::digit2char(static_cast<uint8_t>(remainder.word_at(0)));
         if(copy.is_zero())
            break;
         }
      }
   else
      throw Invalid_Argument("Unknown BigInt encoding method");
   }

/*
* Encode a BigInt
*/
std::vector<uint8_t> BigInt::encode(const BigInt& n, Base base)
   {
   std::vector<uint8_t> output(n.encoded_size(base));
   encode(output.data(), n, base);
   if(base != Binary)
      for(size_t j = 0; j != output.size(); ++j)
         if(output[j] == 0)
            output[j] = '0';
   return output;
   }

/*
* Encode a BigInt
*/
secure_vector<uint8_t> BigInt::encode_locked(const BigInt& n, Base base)
   {
   secure_vector<uint8_t> output(n.encoded_size(base));
   encode(output.data(), n, base);
   if(base != Binary)
      for(size_t j = 0; j != output.size(); ++j)
         if(output[j] == 0)
            output[j] = '0';
   return output;
   }

/*
* Encode a BigInt, with leading 0s if needed
*/
secure_vector<uint8_t> BigInt::encode_1363(const BigInt& n, size_t bytes)
   {
   secure_vector<uint8_t> output(bytes);
   BigInt::encode_1363(output.data(), output.size(), n);
   return output;
   }

//static
void BigInt::encode_1363(uint8_t output[], size_t bytes, const BigInt& n)
   {
   const size_t n_bytes = n.bytes();
   if(n_bytes > bytes)
      throw Encoding_Error("encode_1363: n is too large to encode properly");

   const size_t leading_0s = bytes - n_bytes;
   encode(&output[leading_0s], n, Binary);
   }

/*
* Encode two BigInt, with leading 0s if needed, and concatenate
*/
secure_vector<uint8_t> BigInt::encode_fixed_length_int_pair(const BigInt& n1, const BigInt& n2, size_t bytes)
   {
   secure_vector<uint8_t> output(2 * bytes);
   BigInt::encode_1363(output.data(), bytes, n1);
   BigInt::encode_1363(output.data() + bytes, bytes, n2);
   return output;
   }

/*
* Decode a BigInt
*/
BigInt BigInt::decode(const uint8_t buf[], size_t length, Base base)
   {
   BigInt r;
   if(base == Binary)
      r.binary_decode(buf, length);
   else if(base == Hexadecimal)
      {
      secure_vector<uint8_t> binary;

      if(length % 2)
         {
         // Handle lack of leading 0
         const char buf0_with_leading_0[2] =
            { '0', static_cast<char>(buf[0]) };

         binary = hex_decode_locked(buf0_with_leading_0, 2);

         binary += hex_decode_locked(cast_uint8_ptr_to_char(&buf[1]),
                                     length - 1,
                                     false);
         }
      else
         binary = hex_decode_locked(cast_uint8_ptr_to_char(buf),
                                    length, false);

      r.binary_decode(binary.data(), binary.size());
      }
   else if(base == Decimal)
      {
      for(size_t i = 0; i != length; ++i)
         {
         if(Charset::is_space(buf[i]))
            continue;

         if(!Charset::is_digit(buf[i]))
            throw Invalid_Argument("BigInt::decode: "
                                   "Invalid character in decimal input");

         const uint8_t x = Charset::char2digit(buf[i]);

         if(x >= 10)
            throw Invalid_Argument("BigInt: Invalid decimal string");

         r *= 10;
         r += x;
         }
      }
   else
      throw Invalid_Argument("Unknown BigInt decoding method");
   return r;
   }

}
/*
* BigInt Input/Output
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <ostream>

namespace Botan {

/*
* Write the BigInt into a stream
*/
std::ostream& operator<<(std::ostream& stream, const BigInt& n)
   {
   BigInt::Base base = BigInt::Decimal;
   if(stream.flags() & std::ios::hex)
      base = BigInt::Hexadecimal;
   else if(stream.flags() & std::ios::oct)
      throw Exception("Octal output of BigInt not supported");

   if(n == 0)
      stream.write("0", 1);
   else
      {
      if(n < 0)
         stream.write("-", 1);
      const std::vector<uint8_t> buffer = BigInt::encode(n, base);
      size_t skip = 0;
      while(skip < buffer.size() && buffer[skip] == '0')
         ++skip;
      stream.write(cast_uint8_ptr_to_char(buffer.data()) + skip,
                   buffer.size() - skip);
      }
   if(!stream.good())
      throw Stream_IO_Error("BigInt output operator has failed");
   return stream;
   }

/*
* Read the BigInt from a stream
*/
std::istream& operator>>(std::istream& stream, BigInt& n)
   {
   std::string str;
   std::getline(stream, str);
   if(stream.bad() || (stream.fail() && !stream.eof()))
      throw Stream_IO_Error("BigInt input operator has failed");
   n = BigInt(str);
   return stream;
   }

}
/*
* BigInt Assignment Operators
* (C) 1999-2007 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Addition Operator
*/
BigInt& BigInt::operator+=(const BigInt& y)
   {
   const size_t x_sw = sig_words(), y_sw = y.sig_words();

   const size_t reg_size = std::max(x_sw, y_sw) + 1;
   grow_to(reg_size);

   if(sign() == y.sign())
      bigint_add2(mutable_data(), reg_size - 1, y.data(), y_sw);
   else
      {
      int32_t relative_size = bigint_cmp(data(), x_sw, y.data(), y_sw);

      if(relative_size < 0)
         {
         secure_vector<word> z(reg_size - 1);
         bigint_sub3(z.data(), y.data(), reg_size - 1, data(), x_sw);
         std::swap(m_reg, z);
         set_sign(y.sign());
         }
      else if(relative_size == 0)
         {
         zeroise(m_reg);
         set_sign(Positive);
         }
      else if(relative_size > 0)
         bigint_sub2(mutable_data(), x_sw, y.data(), y_sw);
      }

   return (*this);
   }

/*
* Subtraction Operator
*/
BigInt& BigInt::operator-=(const BigInt& y)
   {
   const size_t x_sw = sig_words(), y_sw = y.sig_words();

   int32_t relative_size = bigint_cmp(data(), x_sw, y.data(), y_sw);

   const size_t reg_size = std::max(x_sw, y_sw) + 1;
   grow_to(reg_size);

   if(relative_size < 0)
      {
      if(sign() == y.sign())
         bigint_sub2_rev(mutable_data(), y.data(), y_sw);
      else
         bigint_add2(mutable_data(), reg_size - 1, y.data(), y_sw);

      set_sign(y.reverse_sign());
      }
   else if(relative_size == 0)
      {
      if(sign() == y.sign())
         {
         clear();
         set_sign(Positive);
         }
      else
         bigint_shl1(mutable_data(), x_sw, 0, 1);
      }
   else if(relative_size > 0)
      {
      if(sign() == y.sign())
         bigint_sub2(mutable_data(), x_sw, y.data(), y_sw);
      else
         bigint_add2(mutable_data(), reg_size - 1, y.data(), y_sw);
      }

   return (*this);
   }

/*
* Multiplication Operator
*/
BigInt& BigInt::operator*=(const BigInt& y)
   {
   const size_t x_sw = sig_words(), y_sw = y.sig_words();
   set_sign((sign() == y.sign()) ? Positive : Negative);

   if(x_sw == 0 || y_sw == 0)
      {
      clear();
      set_sign(Positive);
      }
   else if(x_sw == 1 && y_sw)
      {
      grow_to(y_sw + 2);
      bigint_linmul3(mutable_data(), y.data(), y_sw, word_at(0));
      }
   else if(y_sw == 1 && x_sw)
      {
      grow_to(x_sw + 2);
      bigint_linmul2(mutable_data(), x_sw, y.word_at(0));
      }
   else
      {
      grow_to(size() + y.size());
      secure_vector<word> workspace(size());
      bigint_mul(*this, BigInt(*this), y, workspace.data());
      }

   return (*this);
   }

/*
* Division Operator
*/
BigInt& BigInt::operator/=(const BigInt& y)
   {
   if(y.sig_words() == 1 && is_power_of_2(y.word_at(0)))
      (*this) >>= (y.bits() - 1);
   else
      (*this) = (*this) / y;
   return (*this);
   }

/*
* Modulo Operator
*/
BigInt& BigInt::operator%=(const BigInt& mod)
   {
   return (*this = (*this) % mod);
   }

/*
* Modulo Operator
*/
word BigInt::operator%=(word mod)
   {
   if(mod == 0)
      throw BigInt::DivideByZero();

   if(is_power_of_2(mod))
       {
       word result = (word_at(0) & (mod - 1));
       clear();
       grow_to(2);
       m_reg[0] = result;
       return result;
       }

   word remainder = 0;

   for(size_t j = sig_words(); j > 0; --j)
      remainder = bigint_modop(remainder, word_at(j-1), mod);
   clear();
   grow_to(2);

   if(remainder && sign() == BigInt::Negative)
      m_reg[0] = mod - remainder;
   else
      m_reg[0] = remainder;

   set_sign(BigInt::Positive);

   return word_at(0);
   }

/*
* Left Shift Operator
*/
BigInt& BigInt::operator<<=(size_t shift)
   {
   if(shift)
      {
      const size_t shift_words = shift / MP_WORD_BITS,
                   shift_bits  = shift % MP_WORD_BITS,
                   words = sig_words();

      grow_to(words + shift_words + (shift_bits ? 1 : 0));
      bigint_shl1(mutable_data(), words, shift_words, shift_bits);
      }

   return (*this);
   }

/*
* Right Shift Operator
*/
BigInt& BigInt::operator>>=(size_t shift)
   {
   if(shift)
      {
      const size_t shift_words = shift / MP_WORD_BITS,
                   shift_bits  = shift % MP_WORD_BITS;

      bigint_shr1(mutable_data(), sig_words(), shift_words, shift_bits);

      if(is_zero())
         set_sign(Positive);
      }

   return (*this);
   }

}
/*
* BigInt Binary Operators
* (C) 1999-2007 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Addition Operator
*/
BigInt operator+(const BigInt& x, const BigInt& y)
   {
   const size_t x_sw = x.sig_words(), y_sw = y.sig_words();

   BigInt z(x.sign(), std::max(x_sw, y_sw) + 1);

   if(x.sign() == y.sign())
      bigint_add3(z.mutable_data(), x.data(), x_sw, y.data(), y_sw);
   else
      {
      int32_t relative_size = bigint_cmp(x.data(), x_sw, y.data(), y_sw);

      if(relative_size < 0)
         {
         bigint_sub3(z.mutable_data(), y.data(), y_sw, x.data(), x_sw);
         z.set_sign(y.sign());
         }
      else if(relative_size == 0)
         z.set_sign(BigInt::Positive);
      else if(relative_size > 0)
         bigint_sub3(z.mutable_data(), x.data(), x_sw, y.data(), y_sw);
      }

   return z;
   }

/*
* Subtraction Operator
*/
BigInt operator-(const BigInt& x, const BigInt& y)
   {
   const size_t x_sw = x.sig_words(), y_sw = y.sig_words();

   int32_t relative_size = bigint_cmp(x.data(), x_sw, y.data(), y_sw);

   BigInt z(BigInt::Positive, std::max(x_sw, y_sw) + 1);

   if(relative_size < 0)
      {
      if(x.sign() == y.sign())
         bigint_sub3(z.mutable_data(), y.data(), y_sw, x.data(), x_sw);
      else
         bigint_add3(z.mutable_data(), x.data(), x_sw, y.data(), y_sw);
      z.set_sign(y.reverse_sign());
      }
   else if(relative_size == 0)
      {
      if(x.sign() != y.sign())
         bigint_shl2(z.mutable_data(), x.data(), x_sw, 0, 1);
      }
   else if(relative_size > 0)
      {
      if(x.sign() == y.sign())
         bigint_sub3(z.mutable_data(), x.data(), x_sw, y.data(), y_sw);
      else
         bigint_add3(z.mutable_data(), x.data(), x_sw, y.data(), y_sw);
      z.set_sign(x.sign());
      }
   return z;
   }

/*
* Multiplication Operator
*/
BigInt operator*(const BigInt& x, const BigInt& y)
   {
   const size_t x_sw = x.sig_words(), y_sw = y.sig_words();

   BigInt z(BigInt::Positive, x.size() + y.size());

   if(x_sw == 1 && y_sw)
      bigint_linmul3(z.mutable_data(), y.data(), y_sw, x.word_at(0));
   else if(y_sw == 1 && x_sw)
      bigint_linmul3(z.mutable_data(), x.data(), x_sw, y.word_at(0));
   else if(x_sw && y_sw)
      {
      secure_vector<word> workspace(z.size());
      bigint_mul(z, x, y, workspace.data());
      }

   if(x_sw && y_sw && x.sign() != y.sign())
      z.flip_sign();
   return z;
   }

/*
* Division Operator
*/
BigInt operator/(const BigInt& x, const BigInt& y)
   {
   BigInt q, r;
   divide(x, y, q, r);
   return q;
   }

/*
* Modulo Operator
*/
BigInt operator%(const BigInt& n, const BigInt& mod)
   {
   if(mod.is_zero())
      throw BigInt::DivideByZero();
   if(mod.is_negative())
      throw Invalid_Argument("BigInt::operator%: modulus must be > 0");
   if(n.is_positive() && mod.is_positive() && n < mod)
      return n;

   BigInt q, r;
   divide(n, mod, q, r);
   return r;
   }

/*
* Modulo Operator
*/
word operator%(const BigInt& n, word mod)
   {
   if(mod == 0)
      throw BigInt::DivideByZero();

   if(is_power_of_2(mod))
      return (n.word_at(0) & (mod - 1));

   word remainder = 0;

   for(size_t j = n.sig_words(); j > 0; --j)
      remainder = bigint_modop(remainder, n.word_at(j-1), mod);

   if(remainder && n.sign() == BigInt::Negative)
      return mod - remainder;
   return remainder;
   }

/*
* Left Shift Operator
*/
BigInt operator<<(const BigInt& x, size_t shift)
   {
   if(shift == 0)
      return x;

   const size_t shift_words = shift / MP_WORD_BITS,
                shift_bits  = shift % MP_WORD_BITS;

   const size_t x_sw = x.sig_words();

   BigInt y(x.sign(), x_sw + shift_words + (shift_bits ? 1 : 0));
   bigint_shl2(y.mutable_data(), x.data(), x_sw, shift_words, shift_bits);
   return y;
   }

/*
* Right Shift Operator
*/
BigInt operator>>(const BigInt& x, size_t shift)
   {
   if(shift == 0)
      return x;
   if(x.bits() <= shift)
      return 0;

   const size_t shift_words = shift / MP_WORD_BITS,
                shift_bits  = shift % MP_WORD_BITS,
                x_sw = x.sig_words();

   BigInt y(x.sign(), x_sw - shift_words);
   bigint_shr2(y.mutable_data(), x.data(), x_sw, shift_words, shift_bits);
   return y;
   }

}
/*
* BigInt Random Generation
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Randomize this number
*/
void BigInt::randomize(RandomNumberGenerator& rng,
                       size_t bitsize, bool set_high_bit)
   {
   set_sign(Positive);

   if(bitsize == 0)
      {
      clear();
      }
   else
      {
      secure_vector<uint8_t> array = rng.random_vec(round_up(bitsize, 8) / 8);

      // Always cut unwanted bits
      if(bitsize % 8)
         array[0] &= 0xFF >> (8 - (bitsize % 8));

      // Set the highest bit if wanted
      if (set_high_bit)
         array[0] |= 0x80 >> ((bitsize % 8) ? (8 - bitsize % 8) : 0);

      binary_decode(array);
      }
   }

/*
* Generate a random integer within given range
*/
BigInt BigInt::random_integer(RandomNumberGenerator& rng,
                              const BigInt& min, const BigInt& max)
   {
   BigInt r;

   const size_t bits = max.bits();

   do
      {
      r.randomize(rng, bits, false);
      }
   while(r < min || r >= max);

   return r;
   }

}
/*
* BigInt Base
* (C) 1999-2011,2012,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Construct a BigInt from a regular number
*/
BigInt::BigInt(uint64_t n)
   {
   if(n == 0)
      return;

   const size_t limbs_needed = sizeof(uint64_t) / sizeof(word);

   m_reg.resize(4*limbs_needed);
   for(size_t i = 0; i != limbs_needed; ++i)
      m_reg[i] = ((n >> (i*MP_WORD_BITS)) & MP_WORD_MASK);
   }

/*
* Construct a BigInt of the specified size
*/
BigInt::BigInt(Sign s, size_t size)
   {
   m_reg.resize(round_up(size, 8));
   m_signedness = s;
   }

/*
* Copy constructor
*/
BigInt::BigInt(const BigInt& other)
   {
   m_reg = other.m_reg;
   m_signedness = other.m_signedness;
   }

/*
* Construct a BigInt from a string
*/
BigInt::BigInt(const std::string& str)
   {
   Base base = Decimal;
   size_t markers = 0;
   bool negative = false;

   if(str.length() > 0 && str[0] == '-')
      {
      markers += 1;
      negative = true;
      }

   if(str.length() > markers + 2 && str[markers    ] == '0' &&
                                    str[markers + 1] == 'x')
      {
      markers += 2;
      base = Hexadecimal;
      }

   *this = decode(cast_char_ptr_to_uint8(str.data()) + markers,
                  str.length() - markers, base);

   if(negative) set_sign(Negative);
   else         set_sign(Positive);
   }

/*
* Construct a BigInt from an encoded BigInt
*/
BigInt::BigInt(const uint8_t input[], size_t length, Base base)
   {
   *this = decode(input, length, base);
   }

/*
* Construct a BigInt from an encoded BigInt
*/
BigInt::BigInt(RandomNumberGenerator& rng, size_t bits, bool set_high_bit)
   {
   randomize(rng, bits, set_high_bit);
   }

/*
* Comparison Function
*/
int32_t BigInt::cmp(const BigInt& other, bool check_signs) const
   {
   if(check_signs)
      {
      if(other.is_positive() && this->is_negative())
         return -1;

      if(other.is_negative() && this->is_positive())
         return 1;

      if(other.is_negative() && this->is_negative())
         return (-bigint_cmp(this->data(), this->sig_words(),
                             other.data(), other.sig_words()));
      }

   return bigint_cmp(this->data(), this->sig_words(),
                     other.data(), other.sig_words());
   }

/*
* Return bits {offset...offset+length}
*/
uint32_t BigInt::get_substring(size_t offset, size_t length) const
   {
   if(length > 32)
      throw Invalid_Argument("BigInt::get_substring: Substring size too big");

   uint64_t piece = 0;
   for(size_t i = 0; i != 8; ++i)
      {
      const uint8_t part = byte_at((offset / 8) + (7-i));
      piece = (piece << 8) | part;
      }

   const uint64_t mask = (static_cast<uint64_t>(1) << length) - 1;
   const size_t shift = (offset % 8);

   return static_cast<uint32_t>((piece >> shift) & mask);
   }

/*
* Convert this number to a uint32_t, if possible
*/
uint32_t BigInt::to_u32bit() const
   {
   if(is_negative())
      throw Encoding_Error("BigInt::to_u32bit: Number is negative");
   if(bits() > 32)
      throw Encoding_Error("BigInt::to_u32bit: Number is too big to convert");

   uint32_t out = 0;
   for(size_t i = 0; i != 4; ++i)
      out = (out << 8) | byte_at(3-i);
   return out;
   }

/*
* Set bit number n
*/
void BigInt::set_bit(size_t n)
   {
   const size_t which = n / MP_WORD_BITS;
   const word mask = static_cast<word>(1) << (n % MP_WORD_BITS);
   if(which >= size()) grow_to(which + 1);
   m_reg[which] |= mask;
   }

/*
* Clear bit number n
*/
void BigInt::clear_bit(size_t n)
   {
   const size_t which = n / MP_WORD_BITS;
   const word mask = static_cast<word>(1) << (n % MP_WORD_BITS);
   if(which < size())
      m_reg[which] &= ~mask;
   }

size_t BigInt::bytes() const
   {
   return round_up(bits(), 8) / 8;
   }

/*
* Count how many bits are being used
*/
size_t BigInt::bits() const
   {
   const size_t words = sig_words();

   if(words == 0)
      return 0;

   const size_t full_words = words - 1;
   return (full_words * MP_WORD_BITS + high_bit(word_at(full_words)));
   }

/*
* Calcluate the size in a certain base
*/
size_t BigInt::encoded_size(Base base) const
   {
   static const double LOG_2_BASE_10 = 0.30102999566;

   if(base == Binary)
      return bytes();
   else if(base == Hexadecimal)
      return 2*bytes();
   else if(base == Decimal)
      return static_cast<size_t>((bits() * LOG_2_BASE_10) + 1);
   else
      throw Invalid_Argument("Unknown base for BigInt encoding");
   }

/*
* Set the sign
*/
void BigInt::set_sign(Sign s)
   {
   if(is_zero())
      m_signedness = Positive;
   else
      m_signedness = s;
   }

/*
* Reverse the value of the sign flag
*/
void BigInt::flip_sign()
   {
   set_sign(reverse_sign());
   }

/*
* Return the opposite value of the current sign
*/
BigInt::Sign BigInt::reverse_sign() const
   {
   if(sign() == Positive)
      return Negative;
   return Positive;
   }

/*
* Return the negation of this number
*/
BigInt BigInt::operator-() const
   {
   BigInt x = (*this);
   x.flip_sign();
   return x;
   }

/*
* Return the absolute value of this number
*/
BigInt BigInt::abs() const
   {
   BigInt x = (*this);
   x.set_sign(Positive);
   return x;
   }

void BigInt::grow_to(size_t n)
   {
   if(n > size())
      m_reg.resize(round_up(n, 8));
   }

/*
* Encode this number into bytes
*/
void BigInt::binary_encode(uint8_t output[]) const
   {
   const size_t sig_bytes = bytes();
   for(size_t i = 0; i != sig_bytes; ++i)
      output[sig_bytes-i-1] = byte_at(i);
   }

/*
* Set this number to the value in buf
*/
void BigInt::binary_decode(const uint8_t buf[], size_t length)
   {
   const size_t WORD_BYTES = sizeof(word);

   clear();
   m_reg.resize(round_up((length / WORD_BYTES) + 1, 8));

   for(size_t i = 0; i != length / WORD_BYTES; ++i)
      {
      const size_t top = length - WORD_BYTES*i;
      for(size_t j = WORD_BYTES; j > 0; --j)
         m_reg[i] = (m_reg[i] << 8) | buf[top - j];
      }

   for(size_t i = 0; i != length % WORD_BYTES; ++i)
      m_reg[length / WORD_BYTES] = (m_reg[length / WORD_BYTES] << 8) | buf[i];
   }

void BigInt::shrink_to_fit()
   {
   m_reg.resize(sig_words());
   }

void BigInt::const_time_lookup(secure_vector<word>& output,
                               const std::vector<BigInt>& vec,
                               size_t idx)
   {
   const size_t words = output.size();

   clear_mem(output.data(), output.size());

   CT::poison(&idx, sizeof(idx));

   for(size_t i = 0; i != vec.size(); ++i)
      {
      BOTAN_ASSERT(vec[i].size() >= words,
                   "Word size as expected in const_time_lookup");

      for(size_t w = 0; w != words; ++w)
         output[w] |= CT::select<word>(CT::is_equal(i, idx), vec[i].word_at(w), 0);
      }

   CT::unpoison(idx);
   CT::unpoison(output.data(), output.size());
   }

}
/*
* Division Algorithm
* (C) 1999-2007,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

/*
* Handle signed operands, if necessary
*/
void sign_fixup(const BigInt& x, const BigInt& y, BigInt& q, BigInt& r)
   {
   if(x.sign() == BigInt::Negative)
      {
      q.flip_sign();
      if(r.is_nonzero()) { --q; r = y.abs() - r; }
      }
   if(y.sign() == BigInt::Negative)
      q.flip_sign();
   }

bool division_check(word q, word y2, word y1,
                    word x3, word x2, word x1)
   {
   // Compute (y3,y2,y1) = (y2,y1) * q

   word y3 = 0;
   y1 = word_madd2(q, y1, &y3);
   y2 = word_madd2(q, y2, &y3);

   // Return (y3,y2,y1) >? (x3,x2,x1)

   if(y3 > x3) return true;
   if(y3 < x3) return false;

   if(y2 > x2) return true;
   if(y2 < x2) return false;

   if(y1 > x1) return true;
   if(y1 < x1) return false;

   return false;
   }

}

/*
* Solve x = q * y + r
*/
void divide(const BigInt& x, const BigInt& y_arg, BigInt& q, BigInt& r)
   {
   if(y_arg.is_zero())
      throw BigInt::DivideByZero();

   BigInt y = y_arg;
   const size_t y_words = y.sig_words();

   r = x;
   q = 0;

   r.set_sign(BigInt::Positive);
   y.set_sign(BigInt::Positive);

   int32_t compare = r.cmp(y);

   if(compare == 0)
      {
      q = 1;
      r = 0;
      }
   else if(compare > 0)
      {
      size_t shifts = 0;
      word y_top = y.word_at(y.sig_words()-1);
      while(y_top < MP_WORD_TOP_BIT) { y_top <<= 1; ++shifts; }
      y <<= shifts;
      r <<= shifts;

      const size_t n = r.sig_words() - 1, t = y_words - 1;

      if(n < t)
         throw Internal_Error("BigInt division word sizes");

      q.grow_to(n - t + 1);

      word* q_words = q.mutable_data();

      if(n <= t)
         {
         while(r > y) { r -= y; ++q; }
         r >>= shifts;
         sign_fixup(x, y_arg, q, r);
         return;
         }

      BigInt temp = y << (MP_WORD_BITS * (n-t));

      while(r >= temp) { r -= temp; q_words[n-t] += 1; }

      for(size_t j = n; j != t; --j)
         {
         const word x_j0  = r.word_at(j);
         const word x_j1 = r.word_at(j-1);
         const word y_t  = y.word_at(t);

         if(x_j0 == y_t)
            q_words[j-t-1] = MP_WORD_MAX;
         else
            q_words[j-t-1] = bigint_divop(x_j0, x_j1, y_t);

         while(division_check(q_words[j-t-1],
                              y_t, y.word_at(t-1),
                              x_j0, x_j1, r.word_at(j-2)))
            {
            q_words[j-t-1] -= 1;
            }

         r -= (q_words[j-t-1] * y) << (MP_WORD_BITS * (j-t-1));

         if(r.is_negative())
            {
            r += y << (MP_WORD_BITS * (j-t-1));
            q_words[j-t-1] -= 1;
            }
         }
      r >>= shifts;
      }

   sign_fixup(x, y_arg, q, r);
   }

}
/*
* Block Ciphers
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_AES)
#endif

#if defined(BOTAN_HAS_ARIA)
#endif

#if defined(BOTAN_HAS_BLOWFISH)
#endif

#if defined(BOTAN_HAS_CAMELLIA)
#endif

#if defined(BOTAN_HAS_CAST_128)
#endif

#if defined(BOTAN_HAS_CAST_256)
#endif

#if defined(BOTAN_HAS_CASCADE)
#endif

#if defined(BOTAN_HAS_DES)
#endif

#if defined(BOTAN_HAS_GOST_28147_89)
#endif

#if defined(BOTAN_HAS_IDEA)
#endif

#if defined(BOTAN_HAS_KASUMI)
#endif

#if defined(BOTAN_HAS_LION)
#endif

#if defined(BOTAN_HAS_MISTY1)
#endif

#if defined(BOTAN_HAS_NOEKEON)
#endif

#if defined(BOTAN_HAS_SEED)
#endif

#if defined(BOTAN_HAS_SERPENT)
#endif

#if defined(BOTAN_HAS_SHACAL2)
#endif

#if defined(BOTAN_HAS_SM4)
#endif

#if defined(BOTAN_HAS_TWOFISH)
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
#endif

#if defined(BOTAN_HAS_XTEA)
#endif

#if defined(BOTAN_HAS_OPENSSL)
#endif

namespace Botan {

std::unique_ptr<BlockCipher>
BlockCipher::create(const std::string& algo,
                    const std::string& provider)
   {
#if defined(BOTAN_HAS_OPENSSL)
   if(provider.empty() || provider == "openssl")
      {
      if(auto bc = make_openssl_block_cipher(algo))
         return bc;

      if(!provider.empty())
         return nullptr;
      }
#endif

   // TODO: CommonCrypto
   // TODO: CryptoAPI
   // TODO: /dev/crypto

   // Only base providers from here on out
   if(provider.empty() == false && provider != "base")
      return nullptr;

#if defined(BOTAN_HAS_AES)
   if(algo == "AES-128")
      {
      return std::unique_ptr<BlockCipher>(new AES_128);
      }

   if(algo == "AES-192")
      {
      return std::unique_ptr<BlockCipher>(new AES_192);
      }

   if(algo == "AES-256")
      {
      return std::unique_ptr<BlockCipher>(new AES_256);
      }
#endif

#if defined(BOTAN_HAS_ARIA)
   if(algo == "ARIA-128")
      {
      return std::unique_ptr<BlockCipher>(new ARIA_128);
      }

   if(algo == "ARIA-192")
      {
      return std::unique_ptr<BlockCipher>(new ARIA_192);
      }

   if(algo == "ARIA-256")
      {
      return std::unique_ptr<BlockCipher>(new ARIA_256);
      }
#endif

#if defined(BOTAN_HAS_SERPENT)
   if(algo == "Serpent")
      {
      return std::unique_ptr<BlockCipher>(new Serpent);
      }
#endif

#if defined(BOTAN_HAS_SHACAL2)
   if(algo == "SHACAL2")
      {
      return std::unique_ptr<BlockCipher>(new SHACAL2);
      }
#endif

#if defined(BOTAN_HAS_TWOFISH)
   if(algo == "Twofish")
      {
      return std::unique_ptr<BlockCipher>(new Twofish);
      }
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
   if(algo == "Threefish-512")
      {
      return std::unique_ptr<BlockCipher>(new Threefish_512);
      }
#endif

#if defined(BOTAN_HAS_BLOWFISH)
   if(algo == "Blowfish")
      {
      return std::unique_ptr<BlockCipher>(new Blowfish);
      }
#endif

#if defined(BOTAN_HAS_CAMELLIA)
   if(algo == "Camellia-128")
      {
      return std::unique_ptr<BlockCipher>(new Camellia_128);
      }

   if(algo == "Camellia-192")
      {
      return std::unique_ptr<BlockCipher>(new Camellia_192);
      }

   if(algo == "Camellia-256")
      {
      return std::unique_ptr<BlockCipher>(new Camellia_256);
      }
#endif

#if defined(BOTAN_HAS_DES)
   if(algo == "DES")
      {
      return std::unique_ptr<BlockCipher>(new DES);
      }

   if(algo == "DESX")
      {
      return std::unique_ptr<BlockCipher>(new DESX);
      }

   if(algo == "TripleDES" || algo == "3DES" || algo == "DES-EDE")
      {
      return std::unique_ptr<BlockCipher>(new TripleDES);
      }
#endif

#if defined(BOTAN_HAS_NOEKEON)
   if(algo == "Noekeon")
      {
      return std::unique_ptr<BlockCipher>(new Noekeon);
      }
#endif

#if defined(BOTAN_HAS_CAST_128)
   if(algo == "CAST-128" || algo == "CAST5")
      {
      return std::unique_ptr<BlockCipher>(new CAST_128);
      }
#endif

#if defined(BOTAN_HAS_CAST_256)
   if(algo == "CAST-256")
      {
      return std::unique_ptr<BlockCipher>(new CAST_256);
      }
#endif

#if defined(BOTAN_HAS_IDEA)
   if(algo == "IDEA")
      {
      return std::unique_ptr<BlockCipher>(new IDEA);
      }
#endif

#if defined(BOTAN_HAS_KASUMI)
   if(algo == "KASUMI")
      {
      return std::unique_ptr<BlockCipher>(new KASUMI);
      }
#endif

#if defined(BOTAN_HAS_MISTY1)
   if(algo == "MISTY1")
      {
      return std::unique_ptr<BlockCipher>(new MISTY1);
      }
#endif

#if defined(BOTAN_HAS_SEED)
   if(algo == "SEED")
      {
      return std::unique_ptr<BlockCipher>(new SEED);
      }
#endif

#if defined(BOTAN_HAS_SM4)
   if(algo == "SM4")
      {
      return std::unique_ptr<BlockCipher>(new SM4);
      }
#endif

#if defined(BOTAN_HAS_XTEA)
   if(algo == "XTEA")
      {
      return std::unique_ptr<BlockCipher>(new XTEA);
      }
#endif

   const SCAN_Name req(algo);

#if defined(BOTAN_HAS_GOST_28147_89)
   if(req.algo_name() == "GOST-28147-89")
      {
      return std::unique_ptr<BlockCipher>(new GOST_28147_89(req.arg(0, "R3411_94_TestParam")));
      }
#endif

#if defined(BOTAN_HAS_CASCADE)
   if(req.algo_name() == "Cascade" && req.arg_count() == 2)
      {
      std::unique_ptr<BlockCipher> c1(BlockCipher::create(req.arg(0)));
      std::unique_ptr<BlockCipher> c2(BlockCipher::create(req.arg(1)));

      if(c1 && c2)
         return std::unique_ptr<BlockCipher>(new Cascade_Cipher(c1.release(), c2.release()));
      }
#endif

#if defined(BOTAN_HAS_LION)
   if(req.algo_name() == "Lion" && req.arg_count_between(2, 3))
      {
      std::unique_ptr<HashFunction> hash(HashFunction::create(req.arg(0)));
      std::unique_ptr<StreamCipher> stream(StreamCipher::create(req.arg(1)));

      if(hash && stream)
         {
         const size_t block_size = req.arg_as_integer(2, 1024);
         return std::unique_ptr<BlockCipher>(new Lion(hash.release(), stream.release(), block_size));
         }
      }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
   }

//static
std::unique_ptr<BlockCipher>
BlockCipher::create_or_throw(const std::string& algo,
                             const std::string& provider)
   {
   if(auto bc = BlockCipher::create(algo, provider))
      {
      return bc;
      }
   throw Lookup_Error("Block cipher", algo, provider);
   }

std::vector<std::string> BlockCipher::providers(const std::string& algo)
   {
   return probe_providers_of<BlockCipher>(algo, { "base", "openssl" });
   }

}
/*
* CBC Mode
* (C) 1999-2007,2013,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

CBC_Mode::CBC_Mode(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
   m_cipher(cipher),
   m_padding(padding),
   m_state(m_cipher->block_size())
   {
   if(m_padding && !m_padding->valid_blocksize(cipher->block_size()))
      throw Invalid_Argument("Padding " + m_padding->name() +
                             " cannot be used with " +
                             cipher->name() + "/CBC");
   }

void CBC_Mode::clear()
   {
   m_cipher->clear();
   reset();
   }

void CBC_Mode::reset()
   {
   zeroise(m_state);
   }

std::string CBC_Mode::name() const
   {
   if(m_padding)
      return cipher().name() + "/CBC/" + padding().name();
   else
      return cipher().name() + "/CBC/CTS";
   }

size_t CBC_Mode::update_granularity() const
   {
   return cipher().parallel_bytes();
   }

Key_Length_Specification CBC_Mode::key_spec() const
   {
   return cipher().key_spec();
   }

size_t CBC_Mode::default_nonce_length() const
   {
   return block_size();
   }

bool CBC_Mode::valid_nonce_length(size_t n) const
   {
   return (n == 0 || n == block_size());
   }

void CBC_Mode::key_schedule(const uint8_t key[], size_t length)
   {
   m_cipher->set_key(key, length);
   }

void CBC_Mode::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   /*
   * A nonce of zero length means carry the last ciphertext value over
   * as the new IV, as unfortunately some protocols require this. If
   * this is the first message then we use an IV of all zeros.
   */
   if(nonce_len)
      m_state.assign(nonce, nonce + nonce_len);
   }

size_t CBC_Encryption::minimum_final_size() const
   {
   return 0;
   }

size_t CBC_Encryption::output_length(size_t input_length) const
   {
   if(input_length == 0)
      return block_size();
   else
      return round_up(input_length, block_size());
   }

size_t CBC_Encryption::process(uint8_t buf[], size_t sz)
   {
   const size_t BS = block_size();

   BOTAN_ASSERT(sz % BS == 0, "CBC input is full blocks");
   const size_t blocks = sz / BS;

   if(blocks > 0)
      {
      xor_buf(&buf[0], state_ptr(), BS);
      cipher().encrypt(&buf[0]);

      for(size_t i = 1; i != blocks; ++i)
         {
         xor_buf(&buf[BS*i], &buf[BS*(i-1)], BS);
         cipher().encrypt(&buf[BS*i]);
         }

      state().assign(&buf[BS*(blocks-1)], &buf[BS*blocks]);
      }

   return sz;
   }

void CBC_Encryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");

   const size_t BS = block_size();

   const size_t bytes_in_final_block = (buffer.size()-offset) % BS;

   padding().add_padding(buffer, bytes_in_final_block, BS);

   if((buffer.size()-offset) % BS)
      throw Exception("Did not pad to full block size in " + name());

   update(buffer, offset);
   }

bool CTS_Encryption::valid_nonce_length(size_t n) const
   {
   return (n == block_size());
   }

size_t CTS_Encryption::minimum_final_size() const
   {
   return block_size() + 1;
   }

size_t CTS_Encryption::output_length(size_t input_length) const
   {
   return input_length; // no ciphertext expansion in CTS
   }

void CTS_Encryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   uint8_t* buf = buffer.data() + offset;
   const size_t sz = buffer.size() - offset;

   const size_t BS = block_size();

   if(sz < BS + 1)
      throw Encoding_Error(name() + ": insufficient data to encrypt");

   if(sz % BS == 0)
      {
      update(buffer, offset);

      // swap last two blocks
      for(size_t i = 0; i != BS; ++i)
         std::swap(buffer[buffer.size()-BS+i], buffer[buffer.size()-2*BS+i]);
      }
   else
      {
      const size_t full_blocks = ((sz / BS) - 1) * BS;
      const size_t final_bytes = sz - full_blocks;
      BOTAN_ASSERT(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");

      secure_vector<uint8_t> last(buf + full_blocks, buf + full_blocks + final_bytes);
      buffer.resize(full_blocks + offset);
      update(buffer, offset);

      xor_buf(last.data(), state_ptr(), BS);
      cipher().encrypt(last.data());

      for(size_t i = 0; i != final_bytes - BS; ++i)
         {
         last[i] ^= last[i + BS];
         last[i + BS] ^= last[i];
         }

      cipher().encrypt(last.data());

      buffer += last;
      }
   }

size_t CBC_Decryption::output_length(size_t input_length) const
   {
   return input_length; // precise for CTS, worst case otherwise
   }

size_t CBC_Decryption::minimum_final_size() const
   {
   return block_size();
   }

size_t CBC_Decryption::process(uint8_t buf[], size_t sz)
   {
   const size_t BS = block_size();

   BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
   size_t blocks = sz / BS;

   while(blocks)
      {
      const size_t to_proc = std::min(BS * blocks, m_tempbuf.size());

      cipher().decrypt_n(buf, m_tempbuf.data(), to_proc / BS);

      xor_buf(m_tempbuf.data(), state_ptr(), BS);
      xor_buf(&m_tempbuf[BS], buf, to_proc - BS);
      copy_mem(state_ptr(), buf + (to_proc - BS), BS);

      copy_mem(buf, m_tempbuf.data(), to_proc);

      buf += to_proc;
      blocks -= to_proc / BS;
      }

   return sz;
   }

void CBC_Decryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;

   const size_t BS = block_size();

   if(sz == 0 || sz % BS)
      throw Decoding_Error(name() + ": Ciphertext not a multiple of block size");

   update(buffer, offset);

   const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.size()-BS], BS);
   buffer.resize(buffer.size() - pad_bytes); // remove padding
   if(pad_bytes == 0 && padding().name() != "NoPadding")
      {
      throw Decoding_Error(name());
      }
   }

void CBC_Decryption::reset()
   {
   zeroise(state());
   zeroise(m_tempbuf);
   }

bool CTS_Decryption::valid_nonce_length(size_t n) const
   {
   return (n == block_size());
   }

size_t CTS_Decryption::minimum_final_size() const
   {
   return block_size() + 1;
   }

void CTS_Decryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   const size_t BS = block_size();

   if(sz < BS + 1)
      throw Encoding_Error(name() + ": insufficient data to decrypt");

   if(sz % BS == 0)
      {
      // swap last two blocks

      for(size_t i = 0; i != BS; ++i)
         std::swap(buffer[buffer.size()-BS+i], buffer[buffer.size()-2*BS+i]);

      update(buffer, offset);
      }
   else
      {
      const size_t full_blocks = ((sz / BS) - 1) * BS;
      const size_t final_bytes = sz - full_blocks;
      BOTAN_ASSERT(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");

      secure_vector<uint8_t> last(buf + full_blocks, buf + full_blocks + final_bytes);
      buffer.resize(full_blocks + offset);
      update(buffer, offset);

      cipher().decrypt(last.data());

      xor_buf(last.data(), &last[BS], final_bytes - BS);

      for(size_t i = 0; i != final_bytes - BS; ++i)
         std::swap(last[i], last[i + BS]);

      cipher().decrypt(last.data());
      xor_buf(last.data(), state_ptr(), BS);

      buffer += last;
      }
   }

}
/*
* Runtime CPU detection
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

uint64_t CPUID::g_processor_features = 0;
size_t CPUID::g_cache_line_size = BOTAN_TARGET_CPU_DEFAULT_CACHE_LINE_SIZE;
CPUID::Endian_status CPUID::g_endian_status = ENDIAN_UNKNOWN;

bool CPUID::has_simd_32()
   {
#if defined(BOTAN_TARGET_SUPPORTS_SSE2)
   return CPUID::has_sse2();
#elif defined(BOTAN_TARGET_SUPPORTS_ALTIVEC)
   return CPUID::has_altivec();
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
   return CPUID::has_neon();
#else
   return true;
#endif
   }

//static
std::string CPUID::to_string()
   {
   std::vector<std::string> flags;

#define CPUID_PRINT(flag) do { if(has_##flag()) { flags.push_back(#flag); } } while(0)

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   CPUID_PRINT(sse2);
   CPUID_PRINT(ssse3);
   CPUID_PRINT(sse41);
   CPUID_PRINT(sse42);
   CPUID_PRINT(avx2);
   CPUID_PRINT(avx512f);

   CPUID_PRINT(rdtsc);
   CPUID_PRINT(bmi2);
   CPUID_PRINT(adx);

   CPUID_PRINT(aes_ni);
   CPUID_PRINT(clmul);
   CPUID_PRINT(rdrand);
   CPUID_PRINT(rdseed);
   CPUID_PRINT(intel_sha);
#endif

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   CPUID_PRINT(altivec);
#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
   CPUID_PRINT(neon);
   CPUID_PRINT(arm_sha1);
   CPUID_PRINT(arm_sha2);
   CPUID_PRINT(arm_aes);
   CPUID_PRINT(arm_pmull);
#endif

#undef CPUID_PRINT

   return string_join(flags, ' ');
   }

//static
void CPUID::print(std::ostream& o)
   {
   o << "CPUID flags: " << CPUID::to_string() << "\n";
   }

//static
void CPUID::initialize()
   {
   g_processor_features = 0;

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY) || \
    defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY) || \
    defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   g_processor_features = CPUID::detect_cpu_features(&g_cache_line_size);

#endif

   g_processor_features |= CPUID::CPUID_INITIALIZED_BIT;
   }

//static
CPUID::Endian_status CPUID::runtime_check_endian()
   {
   // Check runtime endian
   const uint32_t endian32 = 0x01234567;
   const uint8_t* e8 = reinterpret_cast<const uint8_t*>(&endian32);

   Endian_status endian = ENDIAN_UNKNOWN;

   if(e8[0] == 0x01 && e8[1] == 0x23 && e8[2] == 0x45 && e8[3] == 0x67)
      {
      endian = ENDIAN_BIG;
      }
   else if(e8[0] == 0x67 && e8[1] == 0x45 && e8[2] == 0x23 && e8[3] == 0x01)
      {
      endian = ENDIAN_LITTLE;
      }
   else
      {
      throw Internal_Error("Unexpected endian at runtime, neither big nor little");
      }

   // If we were compiled with a known endian, verify it matches at runtime
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   BOTAN_ASSERT(endian == ENDIAN_LITTLE, "Build and runtime endian match");
#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   BOTAN_ASSERT(endian == ENDIAN_BIG, "Build and runtime endian match");
#endif

   return endian;
   }

std::vector<Botan::CPUID::CPUID_bits>
CPUID::bit_from_string(const std::string& tok)
   {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   if(tok == "sse2" || tok == "simd")
      return {Botan::CPUID::CPUID_SSE2_BIT};
   if(tok == "ssse3")
      return {Botan::CPUID::CPUID_SSSE3_BIT};
   if(tok == "aesni")
      return {Botan::CPUID::CPUID_AESNI_BIT};
   if(tok == "clmul")
      return {Botan::CPUID::CPUID_CLMUL_BIT};
   if(tok == "avx2")
      return {Botan::CPUID::CPUID_AVX2_BIT};
   if(tok == "sha")
      return {Botan::CPUID::CPUID_SHA_BIT};

#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   if(tok == "altivec" || tok == "simd")
      return {Botan::CPUID::CPUID_ALTIVEC_BIT};

#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
   if(tok == "neon" || tok == "simd")
      return {Botan::CPUID::CPUID_ARM_NEON_BIT};
   if(tok == "armv8sha1")
      return {Botan::CPUID::CPUID_ARM_SHA1_BIT};
   if(tok == "armv8sha2")
      return {Botan::CPUID::CPUID_ARM_SHA2_BIT};
   if(tok == "armv8aes")
      return {Botan::CPUID::CPUID_ARM_AES_BIT};
   if(tok == "armv8pmull")
      return {Botan::CPUID::CPUID_ARM_PMULL_BIT};

#else
   BOTAN_UNUSED(tok);
#endif

   return {};
   }

}
/*
* Runtime CPU detection for ARM
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)

#if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL)
  #include <sys/auxv.h>

#elif defined(BOTAN_TARGET_OS_IS_IOS)
  #include <sys/types.h>
  #include <sys/sysctl.h>

#else

#endif

#endif

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)

#if defined(BOTAN_TARGET_OS_IS_IOS)

namespace {

uint64_t flags_by_ios_machine_type(const std::string& machine)
   {
   /*
   * This relies on a map of known machine names to features. This
   * will quickly grow out of date as new products are introduced, but
   * is apparently the best we can do for iOS.
   */

   struct version_info {
      std::string name;
      size_t min_version_neon;
      size_t min_version_armv8;
      };

   static const version_info min_versions[] = {
      { "iPhone", 2, 6 },
      { "iPad", 1, 4 },
      { "iPod", 4, 7 },
      { "AppleTV", 2, 5 },
   };

   if(machine.size() < 3)
      return 0;

   auto comma = machine.find(',');

   // Simulator, or something we don't know about
   if(comma == std::string::npos)
      return 0;

   std::string product = machine.substr(0, comma);

   size_t version = 0;
   size_t place = 1;
   while(product.size() > 1 && ::isdigit(product.back()))
      {
      const size_t digit = product.back() - '0';
      version += digit * place;
      place *= 10;
      product.pop_back();
      }

   if(version == 0)
      return 0;

   for(const version_info& info : min_versions)
      {
      if(info.name != product)
         continue;

      if(version >= info.min_version_armv8)
         {
         return CPUID::CPUID_ARM_AES_BIT |
                CPUID::CPUID_ARM_PMULL_BIT |
                CPUID::CPUID_ARM_SHA1_BIT |
                CPUID::CPUID_ARM_SHA2_BIT |
                CPUID::CPUID_ARM_NEON_BIT;
         }

      if(version >= info.min_version_neon)
         return CPUID::CPUID_ARM_NEON_BIT;
      }

   // Some other product we don't know about
   return 0;
   }

}

#endif

uint64_t CPUID::detect_cpu_features(size_t* cache_line_size)
   {
   uint64_t detected_features = 0;

#if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL)
   /*
   * On systems with getauxval these bits should normally be defined
   * in bits/auxv.h but some buggy? glibc installs seem to miss them.
   * These following values are all fixed, for the Linux ELF format,
   * so we just hardcode them in ARM_hwcap_bit enum.
   */

   enum ARM_hwcap_bit {
#if defined(BOTAN_TARGET_ARCH_IS_ARM32)
      NEON_bit  = (1 << 12),
      AES_bit   = (1 << 0),
      PMULL_bit = (1 << 1),
      SHA1_bit  = (1 << 2),
      SHA2_bit  = (1 << 3),

      ARCH_hwcap_neon   = 16, // AT_HWCAP
      ARCH_hwcap_crypto = 26, // AT_HWCAP2
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
      NEON_bit  = (1 << 1),
      AES_bit   = (1 << 3),
      PMULL_bit = (1 << 4),
      SHA1_bit  = (1 << 5),
      SHA2_bit  = (1 << 6),

      ARCH_hwcap_neon   = 16, // AT_HWCAP
      ARCH_hwcap_crypto = 16, // AT_HWCAP
#endif
   };

#if defined(AT_DCACHEBSIZE)
   const unsigned long dcache_line = ::getauxval(AT_DCACHEBSIZE);

   // plausibility check
   if(dcache_line == 32 || dcache_line == 64 || dcache_line == 128)
      *cache_line_size = static_cast<size_t>(dcache_line);
#endif

   const unsigned long hwcap_neon = ::getauxval(ARM_hwcap_bit::ARCH_hwcap_neon);
   if(hwcap_neon & ARM_hwcap_bit::NEON_bit)
      detected_features |= CPUID::CPUID_ARM_NEON_BIT;

   /*
   On aarch64 this ends up calling getauxval twice with AT_HWCAP
   It doesn't seem worth optimizing this out, since getauxval is
   just reading a field in the ELF header.
   */
   const unsigned long hwcap_crypto = ::getauxval(ARM_hwcap_bit::ARCH_hwcap_crypto);
   if(hwcap_crypto & ARM_hwcap_bit::AES_bit)
      detected_features |= CPUID::CPUID_ARM_AES_BIT;
   if(hwcap_crypto & ARM_hwcap_bit::PMULL_bit)
      detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
   if(hwcap_crypto & ARM_hwcap_bit::SHA1_bit)
      detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
   if(hwcap_crypto & ARM_hwcap_bit::SHA2_bit)
      detected_features |= CPUID::CPUID_ARM_SHA2_BIT;

#elif defined(BOTAN_TARGET_OS_IS_IOS)

   char machine[64] = { 0 };
   size_t size = sizeof(machine) - 1;
   ::sysctlbyname("hw.machine", machine, &size, nullptr, 0);

   detected_features = flags_by_ios_machine_type(machine);

#elif defined(BOTAN_USE_GCC_INLINE_ASM) && defined(BOTAN_TARGET_ARCH_IS_ARM64)

   /*
   No getauxval API available, fall back on probe functions. We only
   bother with Aarch64 here to simplify the code and because going to
   extreme contortions to support detect NEON on devices that probably
   don't support it doesn't seem worthwhile.

   NEON registers v0-v7 are caller saved in Aarch64
   */

   auto neon_probe  = []() -> int { asm("and v0.16b, v0.16b, v0.16b"); return 1; };
   auto aes_probe   = []() -> int { asm(".word 0x4e284800"); return 1; };
   auto pmull_probe = []() -> int { asm(".word 0x0ee0e000"); return 1; };
   auto sha1_probe  = []() -> int { asm(".word 0x5e280800"); return 1; };
   auto sha2_probe  = []() -> int { asm(".word 0x5e282800"); return 1; };

   // Only bother running the crypto detection if we found NEON

   if(OS::run_cpu_instruction_probe(neon_probe) == 1)
      {
      detected_features |= CPUID::CPUID_ARM_NEON_BIT;

      if(OS::run_cpu_instruction_probe(aes_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_AES_BIT;
      if(OS::run_cpu_instruction_probe(pmull_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
      if(OS::run_cpu_instruction_probe(sha1_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
      if(OS::run_cpu_instruction_probe(sha2_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_SHA2_BIT;
      }

#endif

   return detected_features;
   }

#endif

}
/*
* Runtime CPU detection for POWER/PowerPC
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

/*
* On Darwin and OpenBSD ppc, use sysctl to detect AltiVec
*/
#if defined(BOTAN_TARGET_OS_IS_DARWIN)
  #include <sys/sysctl.h>
#elif defined(BOTAN_TARGET_OS_IS_OPENBSD)
  #include <sys/param.h>
  #include <sys/sysctl.h>
  #include <machine/cpu.h>
#endif

#endif

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

/*
* PowerPC specific block: check for AltiVec using either
* sysctl or by reading processor version number register.
*/
uint64_t CPUID::detect_cpu_features(size_t* cache_line_size)
   {
#if defined(BOTAN_TARGET_OS_IS_DARWIN) || defined(BOTAN_TARGET_OS_IS_OPENBSD)
   // On Darwin/OS X and OpenBSD, use sysctl

   int sels[2] = {
#if defined(BOTAN_TARGET_OS_IS_OPENBSD)
      CTL_MACHDEP, CPU_ALTIVEC
#else
      CTL_HW, HW_VECTORUNIT
#endif
   };

   int vector_type = 0;
   size_t length = sizeof(vector_type);
   int error = ::sysctl(sels, 2, &vector_type, &length, NULL, 0);

   if(error == 0 && vector_type > 0)
      return CPUID::CPUID_ALTIVEC_BIT;

#else

   /*
   On PowerPC, MSR 287 is PVR, the Processor Version Number
   Normally it is only accessible to ring 0, but Linux and NetBSD
   (others, too, maybe?) will trap and emulate it for us.
   */

   int pvr = OS::run_cpu_instruction_probe([]() -> int {
      uint32_t pvr = 0;
      asm volatile("mfspr %0, 287" : "=r" (pvr));
      // Top 16 bits suffice to identify the model
      return static_cast<int>(pvr >> 16);
      });

   if(pvr > 0)
      {
      const uint16_t ALTIVEC_PVR[] = {
         0x003E, // IBM POWER6
         0x003F, // IBM POWER7
         0x004A, // IBM POWER7p
         0x004D, // IBM POWER8
         0x004B, // IBM POWER8E
         0x000C, // G4-7400
         0x0039, // G5 970
         0x003C, // G5 970FX
         0x0044, // G5 970MP
         0x0070, // Cell PPU
         0, // end
      };

      for(size_t i = 0; ALTIVEC_PVR[i]; ++i)
         {
         if(pvr == ALTIVEC_PVR[i])
            return CPUID::CPUID_ALTIVEC_BIT;
         }

      return 0;
      }

   // TODO try direct instruction probing

#endif

   return 0;
   }

#endif

}
/*
* Runtime CPU detection for x86
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
  #include <intrin.h>
#elif defined(BOTAN_BUILD_COMPILER_IS_INTEL)
  #include <ia32intrin.h>
#elif defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)
  #include <cpuid.h>
#endif

#endif

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

uint64_t CPUID::detect_cpu_features(size_t* cache_line_size)
   {
#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
  #define X86_CPUID(type, out) do { __cpuid((int*)out, type); } while(0)
  #define X86_CPUID_SUBLEVEL(type, level, out) do { __cpuidex((int*)out, type, level); } while(0)

#elif defined(BOTAN_BUILD_COMPILER_IS_INTEL)
  #define X86_CPUID(type, out) do { __cpuid(out, type); } while(0)
  #define X86_CPUID_SUBLEVEL(type, level, out) do { __cpuidex((int*)out, type, level); } while(0)

#elif defined(BOTAN_TARGET_ARCH_IS_X86_64) && defined(BOTAN_USE_GCC_INLINE_ASM)
  #define X86_CPUID(type, out)                                                    \
     asm("cpuid\n\t" : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]) \
         : "0" (type))

  #define X86_CPUID_SUBLEVEL(type, level, out)                                    \
     asm("cpuid\n\t" : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]) \
         : "0" (type), "2" (level))

#elif defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)
  #define X86_CPUID(type, out) do { __get_cpuid(type, out, out+1, out+2, out+3); } while(0)

  #define X86_CPUID_SUBLEVEL(type, level, out) \
     do { __cpuid_count(type, level, out[0], out[1], out[2], out[3]); } while(0)
#else
  #warning "No way of calling x86 cpuid instruction for this compiler"
  #define X86_CPUID(type, out) do { clear_mem(out, 4); } while(0)
  #define X86_CPUID_SUBLEVEL(type, level, out) do { clear_mem(out, 4); } while(0)
#endif

   uint64_t features_detected = 0;
   uint32_t cpuid[4] = { 0 };

   // CPUID 0: vendor identification, max sublevel
   X86_CPUID(0, cpuid);

   const uint32_t max_supported_sublevel = cpuid[0];

   const uint32_t INTEL_CPUID[3] = { 0x756E6547, 0x6C65746E, 0x49656E69 };
   const uint32_t AMD_CPUID[3] = { 0x68747541, 0x444D4163, 0x69746E65 };
   const bool is_intel = same_mem(cpuid + 1, INTEL_CPUID, 3);
   const bool is_amd = same_mem(cpuid + 1, AMD_CPUID, 3);

   if(max_supported_sublevel >= 1)
      {
      // CPUID 1: feature bits
      X86_CPUID(1, cpuid);
      const uint64_t flags0 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[3];

      enum x86_CPUID_1_bits : uint64_t {
         RDTSC = (1ULL << 4),
         SSE2 = (1ULL << 26),
         CLMUL = (1ULL << 33),
         SSSE3 = (1ULL << 41),
         SSE41 = (1ULL << 51),
         SSE42 = (1ULL << 52),
         AESNI = (1ULL << 57),
         RDRAND = (1ULL << 62)
      };

      if(flags0 & x86_CPUID_1_bits::RDTSC)
         features_detected |= CPUID::CPUID_RDTSC_BIT;
      if(flags0 & x86_CPUID_1_bits::SSE2)
         features_detected |= CPUID::CPUID_SSE2_BIT;
      if(flags0 & x86_CPUID_1_bits::CLMUL)
         features_detected |= CPUID::CPUID_CLMUL_BIT;
      if(flags0 & x86_CPUID_1_bits::SSSE3)
         features_detected |= CPUID::CPUID_SSSE3_BIT;
      if(flags0 & x86_CPUID_1_bits::SSE41)
         features_detected |= CPUID::CPUID_SSE41_BIT;
      if(flags0 & x86_CPUID_1_bits::SSE42)
         features_detected |= CPUID::CPUID_SSE42_BIT;
      if(flags0 & x86_CPUID_1_bits::AESNI)
         features_detected |= CPUID::CPUID_AESNI_BIT;
      if(flags0 & x86_CPUID_1_bits::RDRAND)
         features_detected |= CPUID::CPUID_RDRAND_BIT;
      }

   if(is_intel)
      {
      // Intel cache line size is in cpuid(1) output
      *cache_line_size = 8 * get_byte(2, cpuid[1]);
      }
   else if(is_amd)
      {
      // AMD puts it in vendor zone
      X86_CPUID(0x80000005, cpuid);
      *cache_line_size = get_byte(3, cpuid[2]);
      }

   if(max_supported_sublevel >= 7)
      {
      clear_mem(cpuid, 4);
      X86_CPUID_SUBLEVEL(7, 0, cpuid);

      enum x86_CPUID_7_bits : uint64_t {
         AVX2 = (1ULL << 5),
         BMI2 = (1ULL << 8),
         AVX512F = (1ULL << 16),
         RDSEED = (1ULL << 18),
         ADX = (1ULL << 19),
         SHA = (1ULL << 29),
      };
      uint64_t flags7 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[1];

      if(flags7 & x86_CPUID_7_bits::AVX2)
         features_detected |= CPUID::CPUID_AVX2_BIT;
      if(flags7 & x86_CPUID_7_bits::BMI2)
         features_detected |= CPUID::CPUID_BMI2_BIT;
      if(flags7 & x86_CPUID_7_bits::AVX512F)
         features_detected |= CPUID::CPUID_AVX512F_BIT;
      if(flags7 & x86_CPUID_7_bits::RDSEED)
         features_detected |= CPUID::CPUID_RDSEED_BIT;
      if(flags7 & x86_CPUID_7_bits::ADX)
         features_detected |= CPUID::CPUID_ADX_BIT;
      if(flags7 & x86_CPUID_7_bits::SHA)
         features_detected |= CPUID::CPUID_SHA_BIT;
      }

#undef X86_CPUID
#undef X86_CPUID_SUBLEVEL

   /*
   * If we don't have access to CPUID, we can still safely assume that
   * any x86-64 processor has SSE2 and RDTSC
   */
#if defined(BOTAN_TARGET_ARCH_IS_X86_64)
   if(features_detected == 0)
      {
      features_detected |= CPUID::CPUID_SSE2_BIT;
      features_detected |= CPUID::CPUID_RDTSC_BIT;
      }
#endif

   return features_detected;
   }

#endif

}
/*
* Discrete Logarithm Parameters
* (C) 1999-2008,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* DL_Group Constructor
*/
DL_Group::DL_Group()
   {
   m_initialized = false;
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(const std::string& name)
   {
   const std::string pem = PEM_for_named_group(name);

   if(pem == "")
      throw Invalid_Argument("DL_Group: Unknown group " + name);

   PEM_decode(pem);
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(RandomNumberGenerator& rng,
                   PrimeType type, size_t pbits, size_t qbits)
   {
   if(pbits < 1024)
      throw Invalid_Argument("DL_Group: prime size " + std::to_string(pbits) +
                             " is too small");

   if(type == Strong)
      {
      m_p = random_safe_prime(rng, pbits);
      m_q = (m_p - 1) / 2;
      m_g = 2;

      /*
      Always choose a generator that is quadratic reside mod p,
      this forces g to be a generator of the subgroup of size q.
      */
      if(jacobi(m_g, m_p) != 1)
         {
         // prime table does not contain 2
         for(size_t i = 0; i < PRIME_TABLE_SIZE; ++i)
            {
            m_g = PRIMES[i];
            if(jacobi(m_g, m_p) == 1)
               break;
            }
         }
      }
   else if(type == Prime_Subgroup)
      {
      if(!qbits)
         qbits = dl_exponent_size(pbits);

      m_q = random_prime(rng, qbits);
      BigInt X;
      while(m_p.bits() != pbits || !is_prime(m_p, rng))
         {
         X.randomize(rng, pbits);
         m_p = X - (X % (2*m_q) - 1);
         }

      m_g = make_dsa_generator(m_p, m_q);
      }
   else if(type == DSA_Kosherizer)
      {
      qbits = qbits ? qbits : ((pbits <= 1024) ? 160 : 256);

      generate_dsa_primes(rng, m_p, m_q, pbits, qbits);

      m_g = make_dsa_generator(m_p, m_q);
      }

   m_initialized = true;
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(RandomNumberGenerator& rng,
                   const std::vector<uint8_t>& seed,
                   size_t pbits, size_t qbits)
   {
   if(!generate_dsa_primes(rng, m_p, m_q, pbits, qbits, seed))
      throw Invalid_Argument("DL_Group: The seed given does not "
                             "generate a DSA group");

   m_g = make_dsa_generator(m_p, m_q);

   m_initialized = true;
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(const BigInt& p1, const BigInt& g1)
   {
   initialize(p1, 0, g1);
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(const BigInt& p1, const BigInt& q1, const BigInt& g1)
   {
   initialize(p1, q1, g1);
   }

/*
* DL_Group Initializer
*/
void DL_Group::initialize(const BigInt& p1, const BigInt& q1, const BigInt& g1)
   {
   if(p1 < 3)
      throw Invalid_Argument("DL_Group: Prime invalid");
   if(g1 < 2 || g1 >= p1)
      throw Invalid_Argument("DL_Group: Generator invalid");
   if(q1 < 0 || q1 >= p1)
      throw Invalid_Argument("DL_Group: Subgroup invalid");

   m_p = p1;
   m_g = g1;
   m_q = q1;

   m_initialized = true;
   }

/*
* Verify that the group has been set
*/
void DL_Group::init_check() const
   {
   if(!m_initialized)
      throw Invalid_State("DLP group cannot be used uninitialized");
   }

/*
* Verify the parameters
*/
bool DL_Group::verify_group(RandomNumberGenerator& rng,
                            bool strong) const
   {
   init_check();

   if(m_g < 2 || m_p < 3 || m_q < 0)
      return false;

   const size_t prob = (strong) ? 128 : 10;

   if(m_q != 0)
      {
      if((m_p - 1) % m_q != 0)
         {
         return false;
         }
      if(power_mod(m_g, m_q, m_p) != 1)
         {
         return false;
         }
      if(!is_prime(m_q, rng, prob))
         {
         return false;
         }
      }
   if(!is_prime(m_p, rng, prob))
      {
      return false;
      }
   return true;
   }

/*
* Return the prime
*/
const BigInt& DL_Group::get_p() const
   {
   init_check();
   return m_p;
   }

/*
* Return the generator
*/
const BigInt& DL_Group::get_g() const
   {
   init_check();
   return m_g;
   }

/*
* Return the subgroup
*/
const BigInt& DL_Group::get_q() const
   {
   init_check();
   if(m_q == 0)
      throw Invalid_State("DLP group has no q prime specified");
   return m_q;
   }

/*
* DER encode the parameters
*/
std::vector<uint8_t> DL_Group::DER_encode(Format format) const
   {
   init_check();

   if((m_q == 0) && (format != PKCS_3))
      throw Encoding_Error("The ANSI DL parameter formats require a subgroup");

   if(format == ANSI_X9_57)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(m_p)
            .encode(m_q)
            .encode(m_g)
         .end_cons()
      .get_contents_unlocked();
      }
   else if(format == ANSI_X9_42)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(m_p)
            .encode(m_g)
            .encode(m_q)
         .end_cons()
      .get_contents_unlocked();
      }
   else if(format == PKCS_3)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(m_p)
            .encode(m_g)
         .end_cons()
      .get_contents_unlocked();
      }

   throw Invalid_Argument("Unknown DL_Group encoding " + std::to_string(format));
   }

/*
* PEM encode the parameters
*/
std::string DL_Group::PEM_encode(Format format) const
   {
   const std::vector<uint8_t> encoding = DER_encode(format);

   if(format == PKCS_3)
      return PEM_Code::encode(encoding, "DH PARAMETERS");
   else if(format == ANSI_X9_57)
      return PEM_Code::encode(encoding, "DSA PARAMETERS");
   else if(format == ANSI_X9_42)
      return PEM_Code::encode(encoding, "X9.42 DH PARAMETERS");
   else
      throw Invalid_Argument("Unknown DL_Group encoding " + std::to_string(format));
   }

/*
* Decode BER encoded parameters
*/
void DL_Group::BER_decode(const std::vector<uint8_t>& data,
                          Format format)
   {
   BigInt new_p, new_q, new_g;

   BER_Decoder decoder(data);
   BER_Decoder ber = decoder.start_cons(SEQUENCE);

   if(format == ANSI_X9_57)
      {
      ber.decode(new_p)
         .decode(new_q)
         .decode(new_g)
         .verify_end();
      }
   else if(format == ANSI_X9_42)
      {
      ber.decode(new_p)
         .decode(new_g)
         .decode(new_q)
         .discard_remaining();
      }
   else if(format == PKCS_3)
      {
      ber.decode(new_p)
         .decode(new_g)
         .discard_remaining();
      }
   else
      throw Invalid_Argument("Unknown DL_Group encoding " + std::to_string(format));

   initialize(new_p, new_q, new_g);
   }

/*
* Decode PEM encoded parameters
*/
void DL_Group::PEM_decode(const std::string& pem)
   {
   std::string label;

   auto ber = unlock(PEM_Code::decode(pem, label));

   if(label == "DH PARAMETERS")
      BER_decode(ber, PKCS_3);
   else if(label == "DSA PARAMETERS")
      BER_decode(ber, ANSI_X9_57);
   else if(label == "X942 DH PARAMETERS" || label == "X9.42 DH PARAMETERS")
      BER_decode(ber, ANSI_X9_42);
   else
      throw Decoding_Error("DL_Group: Invalid PEM label " + label);
   }

/*
* Create generator of the q-sized subgroup (DSA style generator)
*/
BigInt DL_Group::make_dsa_generator(const BigInt& p, const BigInt& q)
   {
   const BigInt e = (p - 1) / q;

   if(e == 0 || (p - 1) % q > 0)
      throw Invalid_Argument("make_dsa_generator q does not divide p-1");

   for(size_t i = 0; i != PRIME_TABLE_SIZE; ++i)
      {
      BigInt g = power_mod(PRIMES[i], e, p);
      if(g > 1)
         return g;
      }

   throw Internal_Error("DL_Group: Couldn't create a suitable generator");
   }

}
/*
* List of discrete log groups
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

std::string DL_Group::PEM_for_named_group(const std::string& name)
   {
   if(name == "modp/ietf/1024")
      return
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIIBCgKBgQD//////////8kP2qIhaMI0xMZii4DcHNEpAk4IimfMdAILvqY7E5si"
         "UUoIeY40BN3vlRmzzTpDGzArCm3yXxQ3T+E1bW1RwkXkhbV2Yl5+xvRMQummN+1r"
         "C/9ctvQGt+3uOGv7Womfpa6fJBF8Sx/mSShmUezmU4H//////////wIBAgKBgH//"
         "////////5IftURC0YRpiYzFFwG4OaJSBJwRFM+Y6AQXfUx2JzZEopQQ8xxoCbvfK"
         "jNnmnSGNmBWFNvkvihun8Jq2tqjhIvJC2rsxLz9jeiYhdNMb9rWF/65begNb9vcc"
         "Nf2tRM/S10+SCL4lj/MklDMo9nMpwP//////////"
         "-----END X942 DH PARAMETERS-----";

   if(name == "modp/srp/1024")
      return
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIIBCgKBgQDurwq5rbON1pwz+Ar6j8XoYHJhh3X/PAueojFMnCVldtZ033SW6oHT"
         "ODtIE9aSxuDg1djiULmL5I5JXB1gidrRXcfXtGFU1rbOjvStabFdSYJVmyl7zxiF"
         "xSn1ZmYOV+xo7bw8BXJswC/Uy/SXbqqa/VE4/oN2Q1ufxh0vwOsG4wIBAgKBgHdX"
         "hVzW2cbrThn8BX1H4vQwOTDDuv+eBc9RGKZOErK7azpvukt1QOmcHaQJ60ljcHBq"
         "7HEoXMXyRySuDrBE7Wiu4+vaMKprW2dHela02K6kwSrNlL3njELilPqzMwcr9jR2"
         "3h4CuTZgF+pl+ku3VU1+qJx/Qbshrc/jDpfgdYNx"
         "-----END X942 DH PARAMETERS-----";

   if(name == "modp/ietf/1536")
      return
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIIBigKBwQD//////////8kP2qIhaMI0xMZii4DcHNEpAk4IimfMdAILvqY7E5si"
         "UUoIeY40BN3vlRmzzTpDGzArCm3yXxQ3T+E1bW1RwkXkhbV2Yl5+xvRMQummN+1r"
         "C/9ctvQGt+3uOGv7Womfpa6fJBF8Sx/mSShmUezkWz3CAHy4oWO/BZjaSDYcVdOa"
         "aRY/qP0kz1+DZV0j3KOtlhxi81YghVK7ntUpB3CWlm1nDDVOSryYBPF0bAjKI3Mn"
         "//////////8CAQICgcB//////////+SH7VEQtGEaYmMxRcBuDmiUgScERTPmOgEF"
         "31Mdic2RKKUEPMcaAm73yozZ5p0hjZgVhTb5L4obp/Catrao4SLyQtq7MS8/Y3om"
         "IXTTG/a1hf+uW3oDW/b3HDX9rUTP0tdPkgi+JY/zJJQzKPZyLZ7hAD5cULHfgsxt"
         "JBsOKunNNIsf1H6SZ6/Bsq6R7lHWyw4xeasQQqldz2qUg7hLSzazhhqnJV5MAni6"
         "NgRlEbmT//////////8="
         "-----END X942 DH PARAMETERS-----";

   if(name == "modp/srp/1536")
      return
         "-----BEGIN DH PARAMETERS-----"
         "MIHHAoHBAJ3vPK+5OSd6sfEqhheke7vbpR30maxMgL7uqWFLGcxNX09fVW4ny95R"
         "xqlL5GB6KRVYkDug0PhDgLZVu5oi6NzfAop87Gfw0IE0sci5eYkUm2CeC+O6tj1H"
         "VIOB28Wx/HZOP0tT3Z2hFYv9PiucjPVu3wGVOTSWJ9sv1T0kt8SGZXcuQ31sf4zk"
         "QnNK98y3roN8Jkrjqb64f4ov6bi1KS5aAh//XpFHnoznoowkQsbzFRgPk0maI03P"
         "duP+0TX5uwIBAg=="
         "-----END DH PARAMETERS-----";

   if(name == "modp/ietf/2048")
      return
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIICDAKCAQEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqsqmj//////////wIBAgKCAQB//////////+SH7VEQtGEa"
         "YmMxRcBuDmiUgScERTPmOgEF31Mdic2RKKUEPMcaAm73yozZ5p0hjZgVhTb5L4ob"
         "p/Catrao4SLyQtq7MS8/Y3omIXTTG/a1hf+uW3oDW/b3HDX9rUTP0tdPkgi+JY/z"
         "JJQzKPZyLZ7hAD5cULHfgsxtJBsOKunNNIsf1H6SZ6/Bsq6R7lHWyw4xeasQQqld"
         "z2qUg7hLSzazhhqnJV5MAni6NgRlDBC+GUgvIxcbZx3xzzuWDAdDAc2TwdF2A9FH"
         "2uKu+DemKWTvFeX7SqwLjBzKpL51SrVyiukTDEx9AogKuUctRVZVNH//////////"
         "-----END X942 DH PARAMETERS-----";

   if(name == "modp/srp/2048")
      return
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIICDAKCAQEArGvbQTJKmpvxZt5eE4lYL69ytmUZh+4H/DGSlD21YFCjcynLtKCZ"
         "7YGT4HV3Z6E91SMSq0sDMQ3Nf0ip2gT9UOgIOWntt2ewz2CVF5oWOrNmGgX71fqq"
         "6CkYqZYvC5O4Vfl5k+yXXuqoDXQK2/T/dHNZ0EHVwz6nHSgeRGsUdzvKl7Q6I/uA"
         "Fna9IHpDbGSB8dK5B4cXRhpbnTLmiPh3SFRFI7UksNV9Xqd6J3XS7PoDLPvb9S+z"
         "eGFgJ5AE5Xrmr4dOcwPOUymczAQce8MI2CpWmPOo0MOCca41+Onb+7aUtcgD2J96"
         "5DXeI21SX1R1m2XjcvzWjvIPpxEfnkr/cwIBAgKCAQBWNe2gmSVNTfizby8JxKwX"
         "17lbMozD9wP+GMlKHtqwKFG5lOXaUEz2wMnwOruz0J7qkYlVpYGYhua/pFTtAn6o"
         "dAQctPbbs9hnsEqLzQsdWbMNAv3q/VV0FIxUyxeFydwq/LzJ9kuvdVQGugVt+n+6"
         "OazoIOrhn1OOlA8iNYo7neVL2h0R/cALO16QPSG2MkD46VyDw4ujDS3OmXNEfDuk"
         "KiKR2pJYar6vU70Tuul2fQGWfe36l9m8MLATyAJyvXNXw6c5gecplM5mAg494YRs"
         "FStMedRoYcE41xr8dO3920pa5AHsT71yGu8RtqkvqjrNsvG5fmtHeQfTiI/PJX+5"
         "-----END X942 DH PARAMETERS-----";

   if(name == "modp/ietf/3072")
      return
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIIDDAKCAYEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqTrS"
         "yv//////////AgECAoIBgH//////////5IftURC0YRpiYzFFwG4OaJSBJwRFM+Y6"
         "AQXfUx2JzZEopQQ8xxoCbvfKjNnmnSGNmBWFNvkvihun8Jq2tqjhIvJC2rsxLz9j"
         "eiYhdNMb9rWF/65begNb9vccNf2tRM/S10+SCL4lj/MklDMo9nItnuEAPlxQsd+C"
         "zG0kGw4q6c00ix/UfpJnr8GyrpHuUdbLDjF5qxBCqV3PapSDuEtLNrOGGqclXkwC"
         "eLo2BGUMEL4ZSC8jFxtnHfHPO5YMB0MBzZPB0XYD0Ufa4q74N6YpZO8V5ftKrAuM"
         "HMqkvnVKtXKK6RMMTH0CiAq5Ry1FVWIW1pmLhoIoPRnUKpDV745dMnZ9woIsbfeF"
         "RXU4q66DBj7Zy4fC03DyY9X610ZthJnrj0ZKcCUSsM7ncekTDWl3NfiX/QNsxQQy"
         "bDsBOZ9kNTIpD5WMC72QBl3wi6u9MK62O4TEYF1so3EEcSfQOnLVmKHtrf5wfohH"
         "JcFokFSdaWV//////////w=="
         "-----END X942 DH PARAMETERS-----";

   if(name == "modp/srp/3072")
      return
         "-----BEGIN DH PARAMETERS-----"
         "MIIBiAKCAYEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqTrS"
         "yv//////////AgEF"
         "-----END DH PARAMETERS-----";

   if(name == "modp/ietf/4096")
      return
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIIEDAKCAgEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
         "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
         "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
         "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0BjGZ//////////8CAQICggIA"
         "f//////////kh+1RELRhGmJjMUXAbg5olIEnBEUz5joBBd9THYnNkSilBDzHGgJu"
         "98qM2eadIY2YFYU2+S+KG6fwmra2qOEi8kLauzEvP2N6JiF00xv2tYX/rlt6A1v2"
         "9xw1/a1Ez9LXT5IIviWP8ySUMyj2ci2e4QA+XFCx34LMbSQbDirpzTSLH9R+kmev"
         "wbKuke5R1ssOMXmrEEKpXc9qlIO4S0s2s4YapyVeTAJ4ujYEZQwQvhlILyMXG2cd"
         "8c87lgwHQwHNk8HRdgPRR9rirvg3pilk7xXl+0qsC4wcyqS+dUq1corpEwxMfQKI"
         "CrlHLUVVYhbWmYuGgig9GdQqkNXvjl0ydn3Cgixt94VFdTirroMGPtnLh8LTcPJj"
         "1frXRm2EmeuPRkpwJRKwzudx6RMNaXc1+Jf9A2zFBDJsOwE5n2Q1MikPlYwLvZAG"
         "XfCLq70wrrY7hMRgXWyjcQRxJ9A6ctWYoe2t/nB+iEclwWiQVJCEAI05HglTw/Nr"
         "xDjNCF7dLZNM4ZOMNXpxHg1KNBpbCoXtEsH05RVqJnRt3eFtgm9HfJdHfgoP32VT"
         "FD4so6c14C7M2Usn0Ehh0RGd0MMorfP2j7CUuGdxa9fcDe67ELgkDmgDSJPq2C1U"
         "ydp1TEbH7uDDf9vuSFNgR6b6GuSaAxjM//////////8="
         "-----END X942 DH PARAMETERS-----";

   if(name == "modp/srp/4096")
      return
         "-----BEGIN DH PARAMETERS-----"
         "MIICCAKCAgEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
         "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
         "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
         "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0BjGZ//////////8CAQU="
         "-----END DH PARAMETERS-----";

   if(name == "modp/ietf/6144")
      return
         "-----BEGIN DSA PARAMETERS-----"
         "MIIGDAKCAwEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
         "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
         "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
         "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG"
         "3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU"
         "7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XId"
         "A/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1ha"
         "xUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/"
         "8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebcxA"
         "JP//////////AoIDAH//////////5IftURC0YRpiYzFFwG4OaJSBJwRFM+Y6AQXf"
         "Ux2JzZEopQQ8xxoCbvfKjNnmnSGNmBWFNvkvihun8Jq2tqjhIvJC2rsxLz9jeiYh"
         "dNMb9rWF/65begNb9vccNf2tRM/S10+SCL4lj/MklDMo9nItnuEAPlxQsd+CzG0k"
         "Gw4q6c00ix/UfpJnr8GyrpHuUdbLDjF5qxBCqV3PapSDuEtLNrOGGqclXkwCeLo2"
         "BGUMEL4ZSC8jFxtnHfHPO5YMB0MBzZPB0XYD0Ufa4q74N6YpZO8V5ftKrAuMHMqk"
         "vnVKtXKK6RMMTH0CiAq5Ry1FVWIW1pmLhoIoPRnUKpDV745dMnZ9woIsbfeFRXU4"
         "q66DBj7Zy4fC03DyY9X610ZthJnrj0ZKcCUSsM7ncekTDWl3NfiX/QNsxQQybDsB"
         "OZ9kNTIpD5WMC72QBl3wi6u9MK62O4TEYF1so3EEcSfQOnLVmKHtrf5wfohHJcFo"
         "kFSQhACNOR4JU8Pza8Q4zQhe3S2TTOGTjDV6cR4NSjQaWwqF7RLB9OUVaiZ0bd3h"
         "bYJvR3yXR34KD99lUxQ+LKOnNeAuzNlLJ9BIYdERndDDKK3z9o+wlLhncWvX3A3u"
         "uxC4JA5oA0iT6tgtVMnadUxGx+7gw3/b7khTYEem+hrkmgFCSRth/VppPjgTYOpu"
         "WTATI29kuo87Ht0b3vx/ygNWzymHcu2cF6CYANdYNSn2yBPsGIvLk9hDLUSMbR9t"
         "9efNinaiZzZdZ2pdje2/iiPzZhKlmZAoqJXr16E33HoAm8ZpX6zB5QDjJcl2eBl1"
         "Cui5DoH6QWvnNzp/e2qvOBejTAZBWtQgGMgFjk8s8+S/32P0eZHUvT8bZkRfB46i"
         "2/+sLWKl6gPZFaCqVWZHtr9fpHDsCmYvaQfAG/BTy4r3eU3xlANQ6sXb4u07eqhV"
         "HsUP3/h1jOZY0Ynqrm0rZPYXeUsZHD/0a7ceAjQCH0ezH6Qwdwlflq2Fujprc0p8"
         "jzbmIBJ//////////wIBAg=="
         "-----END DSA PARAMETERS-----";

   if(name == "modp/srp/6144")
      return
         "-----BEGIN DH PARAMETERS-----"
         "MIIDCAKCAwEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
         "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
         "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
         "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG"
         "3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU"
         "7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XId"
         "A/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1ha"
         "xUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/"
         "8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebcxA"
         "JP//////////AgEF"
         "-----END DH PARAMETERS-----";

   if(name == "modp/ietf/8192")
      return
         "-----BEGIN DSA PARAMETERS-----"
         "MIIIDAKCBAEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
         "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
         "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
         "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG"
         "3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU"
         "7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XId"
         "A/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1ha"
         "xUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/"
         "8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebb4R"
         "WXSjkm8S/uXkOHd8tqky34zYvsTQc7kxujvIMraNndMAdB+nv4r8R+0ldvaTa6Qk"
         "ZjqrY5xa5PVoNCO0dCvxyXgjjxbL451lLeP9uL78hIrZIiIuBKQDfAcT61eoGiPw"
         "xzRz/GRs6jBrS8vIhi+Dhd36nUt/osCH6HloMwPtW906Bis89bOieKZtKhP4P0T4"
         "Ld8xDuB0q2o2RZfomaAlXcFk8xzFCEaFHfmrSBld7X6hsdUQvX7nTXP682vDHs+i"
         "aDWQRvTrh5+SQAlDi0gcbNeImgAu1e44K8kZDab8Am5HlVjkR1Z36aqeMFDidlaU"
         "38gfVuiAuW5xYMmA3Zjt09///////////wKCBAB//////////+SH7VEQtGEaYmMx"
         "RcBuDmiUgScERTPmOgEF31Mdic2RKKUEPMcaAm73yozZ5p0hjZgVhTb5L4obp/Ca"
         "trao4SLyQtq7MS8/Y3omIXTTG/a1hf+uW3oDW/b3HDX9rUTP0tdPkgi+JY/zJJQz"
         "KPZyLZ7hAD5cULHfgsxtJBsOKunNNIsf1H6SZ6/Bsq6R7lHWyw4xeasQQqldz2qU"
         "g7hLSzazhhqnJV5MAni6NgRlDBC+GUgvIxcbZx3xzzuWDAdDAc2TwdF2A9FH2uKu"
         "+DemKWTvFeX7SqwLjBzKpL51SrVyiukTDEx9AogKuUctRVViFtaZi4aCKD0Z1CqQ"
         "1e+OXTJ2fcKCLG33hUV1OKuugwY+2cuHwtNw8mPV+tdGbYSZ649GSnAlErDO53Hp"
         "Ew1pdzX4l/0DbMUEMmw7ATmfZDUyKQ+VjAu9kAZd8IurvTCutjuExGBdbKNxBHEn"
         "0Dpy1Zih7a3+cH6IRyXBaJBUkIQAjTkeCVPD82vEOM0IXt0tk0zhk4w1enEeDUo0"
         "GlsKhe0SwfTlFWomdG3d4W2Cb0d8l0d+Cg/fZVMUPiyjpzXgLszZSyfQSGHREZ3Q"
         "wyit8/aPsJS4Z3Fr19wN7rsQuCQOaANIk+rYLVTJ2nVMRsfu4MN/2+5IU2BHpvoa"
         "5JoBQkkbYf1aaT44E2DqblkwEyNvZLqPOx7dG978f8oDVs8ph3LtnBegmADXWDUp"
         "9sgT7BiLy5PYQy1EjG0fbfXnzYp2omc2XWdqXY3tv4oj82YSpZmQKKiV69ehN9x6"
         "AJvGaV+sweUA4yXJdngZdQrouQ6B+kFr5zc6f3tqrzgXo0wGQVrUIBjIBY5PLPPk"
         "v99j9HmR1L0/G2ZEXweOotv/rC1ipeoD2RWgqlVmR7a/X6Rw7ApmL2kHwBvwU8uK"
         "93lN8ZQDUOrF2+LtO3qoVR7FD9/4dYzmWNGJ6q5tK2T2F3lLGRw/9Gu3HgI0Ah9H"
         "sx+kMHcJX5athbo6a3NKfI823wisulHJN4l/cvIcO75bVJlvxmxfYmg53JjdHeQZ"
         "W0bO6YA6D9PfxX4j9pK7e0m10hIzHVWxzi1yerQaEdo6FfjkvBHHi2XxzrKW8f7c"
         "X35CRWyRERcCUgG+A4n1q9QNEfhjmjn+MjZ1GDWl5eRDF8HC7v1Opb/RYEP0PLQZ"
         "gfat7p0DFZ562dE8UzaVCfwfonwW75iHcDpVtRsiy/RM0BKu4LJ5jmKEI0KO/NWk"
         "DK72v1DY6ohev3Omuf15teGPZ9E0GsgjenXDz8kgBKHFpA42a8RNABdq9xwV5IyG"
         "034BNyPKrHIjqzv01U8YKHE7K0pv5A+rdEBctziwZMBuzHbp7///////////AgEC"
         "-----END DSA PARAMETERS-----";

   if(name == "modp/srp/8192")
      return
         "-----BEGIN DH PARAMETERS-----"
         "MIIECAKCBAEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
         "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
         "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
         "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG"
         "3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU"
         "7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XId"
         "A/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1ha"
         "xUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/"
         "8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebb4R"
         "WXSjkm8S/uXkOHd8tqky34zYvsTQc7kxujvIMraNndMAdB+nv4r8R+0ldvaTa6Qk"
         "ZjqrY5xa5PVoNCO0dCvxyXgjjxbL451lLeP9uL78hIrZIiIuBKQDfAcT61eoGiPw"
         "xzRz/GRs6jBrS8vIhi+Dhd36nUt/osCH6HloMwPtW906Bis89bOieKZtKhP4P0T4"
         "Ld8xDuB0q2o2RZfomaAlXcFk8xzFCEaFHfmrSBld7X6hsdUQvX7nTXP682vDHs+i"
         "aDWQRvTrh5+SQAlDi0gcbNeImgAu1e44K8kZDab8Am5HlVjkR1Z36aqeMFDidlaU"
         "38gfVuiAuW5xYMmA3Zjt09///////////wIBEw=="
         "-----END DH PARAMETERS-----";

   if(name == "dsa/jce/1024")
      return
         "-----BEGIN DSA PARAMETERS-----"
         "MIIBHgKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR+1k9"
         "jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb+DtX"
         "58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdgUI8V"
         "IwvMspK5gqLrhAvwWBz1AoGARpYDUS4wJ4zTlHWV2yLuyYJqYyKtyXNE9B10DDJX"
         "JMj577qn1NgD/4xgnc0QDrxb38+tfGpCX66nhuogUOvpg1HqH9of3yTWlHqmuaoj"
         "dmlTgC9NfUqOy6BtGXaKJJH/sW0O+cQ6mbX3FnL/bwoktETQc20E04oaEyLa9s3Y"
         "jJ0="
         "-----END DSA PARAMETERS-----";

   if(name == "dsa/botan/2048")
      return
         "-----BEGIN DSA PARAMETERS-----"
         "MIICLAKCAQEAkcSKT9+898Aq6V59oSYSK13Shk9Vm4fo50oobVL1m9HeaN/WRdDg"
         "DGDAgAMYkZgDdO61lKUyv9Z7mgnqxLhmOgeRDmjzlGX7cEDSXfE5MuusQ0elMOy6"
         "YchU+biA08DDZgCAWHxFVm2t4mvVo5S+CTtMDyS1r/747GxbPlf7iQJam8FnaZMh"
         "MeFtPJTvyrGNDfBhIDzFPmEDvHLVWUv9QMplOA9EqahR3LB1SV/AM6ilgHGhvXj+"
         "BS9mVVZI60txnSr+i0iA+NrW8VgYuhePiSdMhwvpuW6wjEbEAEDMLv4d+xsYaN0x"
         "nePDSjKmOrbrEiQgmkGWgMx5AtFyjU354QIhAIzX1FD4bwrZTu5M5GmodW0evRBY"
         "JBlD6v+ws1RYXpJNAoIBAA2fXgdhtNvRgz1qsalhoJlsXyIwP3LYTBQPZ8Qx2Uq1"
         "cVvqgaDJjTnOS8941rnryJXTT+idlAkdWEhhXvFfXobxHZb2yWniA936WDVkIKSc"
         "tES1lbkBqTPP4HZ7WU8YoHt/kd7NukRriJkPePL/kfL+fNQ/0uRtGOraH3u2YCxh"
         "f27zpLKE8v2boQo2BC3o+oeiyjZZf+yBFXoUheRAQd8CgwERy4gLvm7UlIFIhvll"
         "zcMTX1zPE4Nyi/ZbgG+WksCxDWxMCcdabKO0ATyxarLBBfa+I66pAA6rIXiYX5cs"
         "mAV+HIbkTnIYaI6krg82NtzKdFydzU5q/7Z8y8E9YTE="
         "-----END DSA PARAMETERS-----";

   if(name == "dsa/botan/3072")
      return
         "-----BEGIN DSA PARAMETERS-----"
         "MIIDLAKCAYEA5LUIgHWWY1heFCRgyi2d/xMviuTIQN2jomZoiRJP5WOLhOiim3rz"
         "+hIJvmv8S1By7Tsrc4e68/hX9HioAijvNgC3az3Pth0g00RlslBtLK+H3259wM6R"
         "vS0Wekb2rcwxxTHk+cervbkq3fNbCoBsZikqX14X6WTdCZkDczrEKKs12A6m9oW/"
         "uovkBo5UGK5eytno/wc94rY+Tn6tNciptwtb1Hz7iNNztm83kxk5sKtxvVWVgJCG"
         "2gFVM30YWg5Ps2pRmxtiArhZHmACRJzxzTpmOE9tIHOxzXO+ypO68eGmEX0COPIi"
         "rh7X/tGFqJDn9n+rj+uXU8wTSlGD3+h64llfe1wtn7tCJJ/dWVE+HTOWs+sv2GaE"
         "8oWoRI/nV6ApiBxAdguU75Gb35dAw4OJWZ7FGm6btRmo4GhJHpzgovz+PLYNZs8N"
         "+tIKjsaEBIaEphREV1vRck1zUrRKdgB3s71r04XOWwpyUMwL92jagpI4Buuc+7E4"
         "hDcxthggjHWbAiEAs+vTZOxp74zzuvZDt1c0sWM5suSeXN4bWcHp+0DuDFsCggGA"
         "K+0h7vg5ZKIwrom7px2ffDnFL8gim047x+WUTTKdoQ8BDqyee69sAJ/E6ylgcj4r"
         "Vt9GY+TDrIAOkljeL3ZJ0gZ4KJP4Ze/KSY0u7zAHTqXop6smJxKk2UovOwuaku5A"
         "D7OKPMWaXcfkNtXABLIuNQKDgbUck0B+sy1K4P1Cy0XhLQ7O6KJiOO3iCCp7FSIR"
         "PGbO+NdFxs88uUX4TS9N4W1Epx3hmCcOE/A1U8iLjTI60LlIob8hA6lJl5tu0W+1"
         "88lT2Vt8jojKZ9z1pjb7nKOdkkIV96iE7Wx+48ltjZcVQnl0t8Q1EoLhPTdz99KL"
         "RS8QiSoTx1hzKN6kgntrNpsqjcFyrcWD9R8qZZjFSD5bxGewL5HQWcQC0Y4sJoD3"
         "dqoG9JKAoscsF8xC1bbnQMXEsas8UcLtCSviotiwU65Xc9FCXtKwjwbi3VBZLfGk"
         "eMFVkc39EVZP+I/zi3IdQjkv2kcyEtz9jS2IqXagCv/m//tDCjWeZMorNRyiQSOU"
         "-----END DSA PARAMETERS-----";

   if(name == "ffdhe/ietf/2048")
      return
         "-----BEGIN DSA PARAMETERS-----"
         "MIICDAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz"
         "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a"
         "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7"
         "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi"
         "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD"
         "ssbzSibBsu/6iGtCOGEoXJf//////////wKCAQB//////////9b8KixRXaVNV+4r"
         "EBOennjsXOLB5xabStTwmyCKMhn95knO5xJNn3y+l/GxsYY67HtA2QFXYjC9ae+P"
         "aur+srCSGfqPr4M3aEKxsqqe9o152quJrz+r5JrMJ4Y4cHNFu/FTRO159/Q5Dvis"
         "UJtW85qYVmUnpB08vV4FWMFZkn2w6IRUpdlkcf3ctW1bsGv6NA6noVHvHKb6Vyt2"
         "87G5XYyFg9PkdwU2uE8BfnDm+/F2YBoCZpQaF7DIuX9OdMLB/8cniRl3eUDB4f8d"
         "jaY31rmd2v5eF2EQAuLHeMG+i0HZY3mlE2DZd/1ENaEcMJQuS///////////AgEC"
         "-----END DSA PARAMETERS-----";

   if(name == "ffdhe/ietf/3072")
      return
         "-----BEGIN DSA PARAMETERS-----"
         "MIIDDAKCAYEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz"
         "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a"
         "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7"
         "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi"
         "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD"
         "ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3"
         "7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32"
         "nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZsYu"
         "N///////////AoIBgH//////////1vwqLFFdpU1X7isQE56eeOxc4sHnFptK1PCb"
         "IIoyGf3mSc7nEk2ffL6X8bGxhjrse0DZAVdiML1p749q6v6ysJIZ+o+vgzdoQrGy"
         "qp72jXnaq4mvP6vkmswnhjhwc0W78VNE7Xn39DkO+KxQm1bzmphWZSekHTy9XgVY"
         "wVmSfbDohFSl2WRx/dy1bVuwa/o0DqehUe8cpvpXK3bzsbldjIWD0+R3BTa4TwF+"
         "cOb78XZgGgJmlBoXsMi5f050wsH/xyeJGXd5QMHh/x2NpjfWuZ3a/l4XYRAC4sd4"
         "wb6LQdljeaUTYNl3/UQ1oRwwj+fubxqtnbKMga3eGnpvfM4BHDDaN+Trc2SDvWyO"
         "k0j7+/csxlh9YMNsjld/CYTCick4WgmGSd4hvKJ6fqIpcWum6bJ5cQ84+qX/rldB"
         "Vc5O+090NpXikRsdBtXikMvNhvVtDt/NIWriJCcFXmg1/Snu954NkHcf6s6+EvIO"
         "lbNjFxv//////////wIBAg=="
         "-----END DSA PARAMETERS-----";

   if(name == "ffdhe/ietf/4096")
      return
         "-----BEGIN DSA PARAMETERS-----"
         "MIIEDAKCAgEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz"
         "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a"
         "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7"
         "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi"
         "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD"
         "ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3"
         "7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32"
         "nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZp4e"
         "8W5vUsMWTfT7eTDp5OWIV7asfV9C1p9tGHdjzx1VA0AEh/VbpX4xzHpxNciG77Qx"
         "iu1qHgEtnmgyqQdgCpGBMMRtx3j5ca0AOAkpmaMzy4t6Gh25PXFAADwqTs6p+Y0K"
         "zAqCkc3OyX3Pjsm1Wn+IpGtNtahR9EGC4caKAH5eZV9q//////////8CggIAf///"
         "///////W/CosUV2lTVfuKxATnp547FziwecWm0rU8JsgijIZ/eZJzucSTZ98vpfx"
         "sbGGOux7QNkBV2IwvWnvj2rq/rKwkhn6j6+DN2hCsbKqnvaNedqria8/q+SazCeG"
         "OHBzRbvxU0Tteff0OQ74rFCbVvOamFZlJ6QdPL1eBVjBWZJ9sOiEVKXZZHH93LVt"
         "W7Br+jQOp6FR7xym+lcrdvOxuV2MhYPT5HcFNrhPAX5w5vvxdmAaAmaUGhewyLl/"
         "TnTCwf/HJ4kZd3lAweH/HY2mN9a5ndr+XhdhEALix3jBvotB2WN5pRNg2Xf9RDWh"
         "HDCP5+5vGq2dsoyBrd4aem98zgEcMNo35OtzZIO9bI6TSPv79yzGWH1gw2yOV38J"
         "hMKJyThaCYZJ3iG8onp+oilxa6bpsnlxDzj6pf+uV0FVzk77T3Q2leKRGx0G1eKQ"
         "y82G9W0O380hauIkJwVeaDX9Ke73ng2Qdx/qzr4S8g6Vs08PeLc3qWGLJvp9vJh0"
         "8nLEK9tWPq+ha0+2jDux546qgaACQ/qt0r8Y5j04muRDd9oYxXa1DwCWzzQZVIOw"
         "BUjAmGI247x8uNaAHASUzNGZ5cW9DQ7cnrigAB4VJ2dU/MaFZgVBSObnZL7nx2Ta"
         "rT/EUjWm2tQo+iDBcONFAD8vMq+1f/////////8CAQI="
         "-----END DSA PARAMETERS-----";

   if(name == "ffdhe/ietf/6144")
      return
         "-----BEGIN DSA PARAMETERS-----"
         "MIIGDAKCAwEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz"
         "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a"
         "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7"
         "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi"
         "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD"
         "ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3"
         "7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32"
         "nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZp4e"
         "8W5vUsMWTfT7eTDp5OWIV7asfV9C1p9tGHdjzx1VA0AEh/VbpX4xzHpxNciG77Qx"
         "iu1qHgEtnmgyqQdgCpGBMMRtx3j5ca0AOAkpmaMzy4t6Gh25PXFAADwqTs6p+Y0K"
         "zAqCkc3OyX3Pjsm1Wn+IpGtNtahR9EGC4caKAH5eDdkCC/1ktkUDbHpOZ30sOFMq"
         "OiO6RELK9T6mO7RUMpt2JMiRe91kscD9TLOOjDNMcBw6za0GV/zP7HGbH1w+TkYE"
         "HziBR/tM/bR3pSRx96mpaRC4VTIu22NA2KAO8JI1BRHjCr7B//njom5/sp+MGDAj"
         "w1h+ONoAd9m0dj5OS5Syu8GUxmUed8r5ku6qwCMqKBv2s6c5wSJhFoIK6NtYR6Z8"
         "vvnJCRtGLVOM1ysDdGrnf15iKSwxFWKoRlBdyC24VDOK5J9SNclbkReMzy3Vys70"
         "A+ydGBDGJysEWztx+dxrgNY/3UqOmtseaWKmlSbUMWHBpB1XDXk42tSkDjKc0OQO"
         "Zf//////////AoIDAH//////////1vwqLFFdpU1X7isQE56eeOxc4sHnFptK1PCb"
         "IIoyGf3mSc7nEk2ffL6X8bGxhjrse0DZAVdiML1p749q6v6ysJIZ+o+vgzdoQrGy"
         "qp72jXnaq4mvP6vkmswnhjhwc0W78VNE7Xn39DkO+KxQm1bzmphWZSekHTy9XgVY"
         "wVmSfbDohFSl2WRx/dy1bVuwa/o0DqehUe8cpvpXK3bzsbldjIWD0+R3BTa4TwF+"
         "cOb78XZgGgJmlBoXsMi5f050wsH/xyeJGXd5QMHh/x2NpjfWuZ3a/l4XYRAC4sd4"
         "wb6LQdljeaUTYNl3/UQ1oRwwj+fubxqtnbKMga3eGnpvfM4BHDDaN+Trc2SDvWyO"
         "k0j7+/csxlh9YMNsjld/CYTCick4WgmGSd4hvKJ6fqIpcWum6bJ5cQ84+qX/rldB"
         "Vc5O+090NpXikRsdBtXikMvNhvVtDt/NIWriJCcFXmg1/Snu954NkHcf6s6+EvIO"
         "lbNPD3i3N6lhiyb6fbyYdPJyxCvbVj6voWtPtow7seeOqoGgAkP6rdK/GOY9OJrk"
         "Q3faGMV2tQ8Als80GVSDsAVIwJhiNuO8fLjWgBwElMzRmeXFvQ0O3J64oAAeFSdn"
         "VPzGhWYFQUjm52S+58dk2q0/xFI1ptrUKPogwXDjRQA/LwbsgQX+slsigbY9JzO+"
         "lhwplR0R3SIhZXqfUx3aKhlNuxJkSL3usljgfqZZx0YZpjgOHWbWgyv+Z/Y4zY+u"
         "HycjAg+cQKP9pn7aO9KSOPvU1LSIXCqZF22xoGxQB3hJGoKI8YVfYP/88dE3P9lP"
         "xgwYEeGsPxxtADvs2jsfJyXKWV3gymMyjzvlfMl3VWARlRQN+1nTnOCRMItBBXRt"
         "rCPTPl985ISNoxapxmuVgbo1c7+vMRSWGIqxVCMoLuQW3CoZxXJPqRrkrciLxmeW"
         "6uVnegH2TowIYxOVgi2duPzuNcBrH+6lR01tjzSxU0qTahiw4NIOq4a8nG1qUgcZ"
         "TmhyBzL//////////wIBAg=="
         "-----END DSA PARAMETERS-----";

   if(name == "ffdhe/ietf/8192")
      return
         "-----BEGIN DSA PARAMETERS-----"
         "MIIIDAKCBAEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz"
         "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a"
         "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7"
         "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi"
         "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD"
         "ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3"
         "7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32"
         "nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZp4e"
         "8W5vUsMWTfT7eTDp5OWIV7asfV9C1p9tGHdjzx1VA0AEh/VbpX4xzHpxNciG77Qx"
         "iu1qHgEtnmgyqQdgCpGBMMRtx3j5ca0AOAkpmaMzy4t6Gh25PXFAADwqTs6p+Y0K"
         "zAqCkc3OyX3Pjsm1Wn+IpGtNtahR9EGC4caKAH5eDdkCC/1ktkUDbHpOZ30sOFMq"
         "OiO6RELK9T6mO7RUMpt2JMiRe91kscD9TLOOjDNMcBw6za0GV/zP7HGbH1w+TkYE"
         "HziBR/tM/bR3pSRx96mpaRC4VTIu22NA2KAO8JI1BRHjCr7B//njom5/sp+MGDAj"
         "w1h+ONoAd9m0dj5OS5Syu8GUxmUed8r5ku6qwCMqKBv2s6c5wSJhFoIK6NtYR6Z8"
         "vvnJCRtGLVOM1ysDdGrnf15iKSwxFWKoRlBdyC24VDOK5J9SNclbkReMzy3Vys70"
         "A+ydGBDGJysEWztx+dxrgNY/3UqOmtseaWKmlSbUMWHBpB1XDXk42tSkDjKcz/Rq"
         "qjatAEz2AMg4HkJaMdlRrmT9sj/OyVCdQ2h/62nt0cxeC4zDvfZLEO+GtjFCo6uI"
         "KVVbL3R8kyZlyywPHMAb1wIpOIg50q8F5FRQSseLdYKCKEbAujXDX1xZFgzARv2C"
         "UVQfxoychrAiu3CZh2pGDnRRqKkxCXA/7hwhfmw4JuUsUappHg5CPPyZ6eMWUMEh"
         "e2JIFs2tmpX51bgBlIjZwKCh/jB1pXfiMYP4HUo/L6RXHvyM4LqKT+i2hV3+crCm"
         "bt7S+6v75Yow+vq+HF1xqH4vdB74wf6G/qa7/eUwZ38Nl9EdSfeoRD0IIuUGqfRh"
         "TgEeKpSDj/iM1oyLt8XGQkz//////////wKCBAB//////////9b8KixRXaVNV+4r"
         "EBOennjsXOLB5xabStTwmyCKMhn95knO5xJNn3y+l/GxsYY67HtA2QFXYjC9ae+P"
         "aur+srCSGfqPr4M3aEKxsqqe9o152quJrz+r5JrMJ4Y4cHNFu/FTRO159/Q5Dvis"
         "UJtW85qYVmUnpB08vV4FWMFZkn2w6IRUpdlkcf3ctW1bsGv6NA6noVHvHKb6Vyt2"
         "87G5XYyFg9PkdwU2uE8BfnDm+/F2YBoCZpQaF7DIuX9OdMLB/8cniRl3eUDB4f8d"
         "jaY31rmd2v5eF2EQAuLHeMG+i0HZY3mlE2DZd/1ENaEcMI/n7m8arZ2yjIGt3hp6"
         "b3zOARww2jfk63Nkg71sjpNI+/v3LMZYfWDDbI5XfwmEwonJOFoJhkneIbyien6i"
         "KXFrpumyeXEPOPql/65XQVXOTvtPdDaV4pEbHQbV4pDLzYb1bQ7fzSFq4iQnBV5o"
         "Nf0p7veeDZB3H+rOvhLyDpWzTw94tzepYYsm+n28mHTycsQr21Y+r6FrT7aMO7Hn"
         "jqqBoAJD+q3SvxjmPTia5EN32hjFdrUPAJbPNBlUg7AFSMCYYjbjvHy41oAcBJTM"
         "0Znlxb0NDtyeuKAAHhUnZ1T8xoVmBUFI5udkvufHZNqtP8RSNaba1Cj6IMFw40UA"
         "Py8G7IEF/rJbIoG2PSczvpYcKZUdEd0iIWV6n1Md2ioZTbsSZEi97rJY4H6mWcdG"
         "GaY4Dh1m1oMr/mf2OM2Prh8nIwIPnECj/aZ+2jvSkjj71NS0iFwqmRdtsaBsUAd4"
         "SRqCiPGFX2D//PHRNz/ZT8YMGBHhrD8cbQA77No7Hyclylld4MpjMo875XzJd1Vg"
         "EZUUDftZ05zgkTCLQQV0bawj0z5ffOSEjaMWqcZrlYG6NXO/rzEUlhiKsVQjKC7k"
         "FtwqGcVyT6ka5K3Ii8ZnlurlZ3oB9k6MCGMTlYItnbj87jXAax/upUdNbY80sVNK"
         "k2oYsODSDquGvJxtalIHGU5n+jVVG1aAJnsAZBwPIS0Y7KjXMn7ZH+dkqE6htD/1"
         "tPbo5i8FxmHe+yWId8NbGKFR1cQUqq2Xuj5JkzLllgeOYA3rgRScRBzpV4LyKigl"
         "Y8W6wUEUI2BdGuGvriyLBmAjfsEoqg/jRk5DWBFduEzDtSMHOijUVJiEuB/3DhC/"
         "NhwTcpYo1TSPByEefkz08YsoYJC9sSQLZtbNSvzq3ADKRGzgUFD/GDrSu/EYwfwO"
         "pR+X0iuPfkZwXUUn9FtCrv85WFM3b2l91f3yxRh9fV8OLrjUPxe6D3xg/0N/U13+"
         "8pgzv4bL6I6k+9QiHoQRcoNU+jCnAI8VSkHH/EZrRkXb4uMhJn//////////AgEC"
         "-----END DSA PARAMETERS-----";

   return "";
   }

}
/*
* Entropy Source Polling
* (C) 2008-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_SYSTEM_RNG)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DARWIN_SECRANDOM)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_GETENTROPY)
#endif

namespace Botan {

#if defined(BOTAN_HAS_SYSTEM_RNG)

namespace {

class System_RNG_EntropySource final : public Entropy_Source
   {
   public:
      size_t poll(RandomNumberGenerator& rng) override
         {
         const size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS;
         rng.reseed_from_rng(system_rng(), poll_bits);
         return poll_bits;
         }

      std::string name() const override { return system_rng().name(); }
   };

}

#endif

std::unique_ptr<Entropy_Source> Entropy_Source::create(const std::string& name)
   {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   if(name == "system_rng" || name == "win32_cryptoapi")
      {
      return std::unique_ptr<Entropy_Source>(new System_RNG_EntropySource);
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
   if(name == "rdrand")
      {
      return std::unique_ptr<Entropy_Source>(new Intel_Rdrand);
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
   if(name == "rdseed")
      {
      return std::unique_ptr<Entropy_Source>(new Intel_Rdseed);
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DARWIN_SECRANDOM)
   if(name == "darwin_secrandom")
      {
      return std::unique_ptr<Entropy_Source>(new Darwin_SecRandom);
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_GETENTROPY)
   if(name == "getentropy")
      {
      return std::unique_ptr<Entropy_Source>(new Getentropy);
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
   if(name == "dev_random")
      {
      return std::unique_ptr<Entropy_Source>(new Device_EntropySource(BOTAN_SYSTEM_RNG_POLL_DEVICES));
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
   if(name == "proc_walk")
      {
      const std::string root_dir = BOTAN_ENTROPY_PROC_FS_PATH;
      if(!root_dir.empty())
         return std::unique_ptr<Entropy_Source>(new ProcWalking_EntropySource(root_dir));
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
   if(name == "system_stats")
      {
      return std::unique_ptr<Entropy_Source>(new Win32_EntropySource);
      }
#endif

   return std::unique_ptr<Entropy_Source>();
   }

void Entropy_Sources::add_source(std::unique_ptr<Entropy_Source> src)
   {
   if(src.get())
      {
      m_srcs.push_back(std::move(src));
      }
   }

std::vector<std::string> Entropy_Sources::enabled_sources() const
   {
   std::vector<std::string> sources;
   for(size_t i = 0; i != m_srcs.size(); ++i)
      {
      sources.push_back(m_srcs[i]->name());
      }
   return sources;
   }

size_t Entropy_Sources::poll(RandomNumberGenerator& rng,
                             size_t poll_bits,
                             std::chrono::milliseconds timeout)
   {
   typedef std::chrono::system_clock clock;

   auto deadline = clock::now() + timeout;

   size_t bits_collected = 0;

   for(size_t i = 0; i != m_srcs.size(); ++i)
      {
      bits_collected += m_srcs[i]->poll(rng);

      if (bits_collected >= poll_bits || clock::now() > deadline)
         break;
      }

   return bits_collected;
   }

size_t Entropy_Sources::poll_just(RandomNumberGenerator& rng, const std::string& the_src)
   {
   for(size_t i = 0; i != m_srcs.size(); ++i)
      {
      if(m_srcs[i]->name() == the_src)
         {
         return m_srcs[i]->poll(rng);
         }
      }

   return 0;
   }

Entropy_Sources::Entropy_Sources(const std::vector<std::string>& sources)
   {
   for(auto&& src_name : sources)
      {
      add_source(Entropy_Source::create(src_name));
      }
   }

Entropy_Sources& Entropy_Sources::global_sources()
   {
   static Entropy_Sources global_entropy_sources(BOTAN_ENTROPY_DEFAULT_SOURCES);

   return global_entropy_sources;
   }

}

/*
* Hash Functions
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_ADLER32)
#endif

#if defined(BOTAN_HAS_CRC24)
#endif

#if defined(BOTAN_HAS_CRC32)
#endif

#if defined(BOTAN_HAS_GOST_34_11)
#endif

#if defined(BOTAN_HAS_KECCAK)
#endif

#if defined(BOTAN_HAS_MD4)
#endif

#if defined(BOTAN_HAS_MD5)
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
#endif

#if defined(BOTAN_HAS_SHA1)
#endif

#if defined(BOTAN_HAS_SHA2_32)
#endif

#if defined(BOTAN_HAS_SHA2_64)
#endif

#if defined(BOTAN_HAS_SHA3)
#endif

#if defined(BOTAN_HAS_SHAKE)
#endif

#if defined(BOTAN_HAS_SKEIN_512)
#endif

#if defined(BOTAN_HAS_STREEBOG)
#endif

#if defined(BOTAN_HAS_SM3)
#endif

#if defined(BOTAN_HAS_TIGER)
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)
#endif

#if defined(BOTAN_HAS_COMB4P)
#endif

#if defined(BOTAN_HAS_BLAKE2B)
#endif

#if defined(BOTAN_HAS_BEARSSL)
#endif

#if defined(BOTAN_HAS_OPENSSL)
#endif

namespace Botan {

std::unique_ptr<HashFunction> HashFunction::create(const std::string& algo_spec,
                                                   const std::string& provider)
   {
#if defined(BOTAN_HAS_OPENSSL)
   if(provider.empty() || provider == "openssl")
      {
      if(auto hash = make_openssl_hash(algo_spec))
         return hash;

      if(!provider.empty())
         return nullptr;
      }
#endif

#if defined(BOTAN_HAS_BEARSSL)
   if(provider.empty() || provider == "bearssl")
      {
      if(auto hash = make_bearssl_hash(algo_spec))
         return hash;

      if(!provider.empty())
         return nullptr;
      }
#endif

   // TODO: CommonCrypto hashes

   if(provider.empty() == false && provider != "base")
      return nullptr; // unknown provider

#if defined(BOTAN_HAS_SHA1)
   if(algo_spec == "SHA-160" ||
      algo_spec == "SHA-1" ||
      algo_spec == "SHA1")
      {
      return std::unique_ptr<HashFunction>(new SHA_160);
      }
#endif

#if defined(BOTAN_HAS_SHA2_32)
   if(algo_spec == "SHA-224")
      {
      return std::unique_ptr<HashFunction>(new SHA_224);
      }

   if(algo_spec == "SHA-256")
      {
      return std::unique_ptr<HashFunction>(new SHA_256);
      }
#endif

#if defined(BOTAN_HAS_SHA2_64)
   if(algo_spec == "SHA-384")
      {
      return std::unique_ptr<HashFunction>(new SHA_384);
      }

   if(algo_spec == "SHA-512")
      {
      return std::unique_ptr<HashFunction>(new SHA_512);
      }

   if(algo_spec == "SHA-512-256")
      {
      return std::unique_ptr<HashFunction>(new SHA_512_256);
      }
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
   if(algo_spec == "RIPEMD-160")
      {
      return std::unique_ptr<HashFunction>(new RIPEMD_160);
      }
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
   if(algo_spec == "Whirlpool")
      {
      return std::unique_ptr<HashFunction>(new Whirlpool);
      }
#endif

#if defined(BOTAN_HAS_MD5)
   if(algo_spec == "MD5")
      {
      return std::unique_ptr<HashFunction>(new MD5);
      }
#endif

#if defined(BOTAN_HAS_MD4)
   if(algo_spec == "MD4")
      {
      return std::unique_ptr<HashFunction>(new MD4);
      }
#endif

#if defined(BOTAN_HAS_GOST_34_11)
   if(algo_spec == "GOST-R-34.11-94" || algo_spec == "GOST-34.11")
      {
      return std::unique_ptr<HashFunction>(new GOST_34_11);
      }
#endif

#if defined(BOTAN_HAS_ADLER32)
   if(algo_spec == "Adler32")
      {
      return std::unique_ptr<HashFunction>(new Adler32);
      }
#endif

#if defined(BOTAN_HAS_CRC24)
   if(algo_spec == "CRC24")
      {
      return std::unique_ptr<HashFunction>(new CRC24);
      }
#endif

#if defined(BOTAN_HAS_CRC32)
   if(algo_spec == "CRC32")
      {
      return std::unique_ptr<HashFunction>(new CRC32);
      }
#endif

   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_TIGER)
   if(req.algo_name() == "Tiger")
      {
      return std::unique_ptr<HashFunction>(
         new Tiger(req.arg_as_integer(0, 24),
                   req.arg_as_integer(1, 3)));
      }
#endif

#if defined(BOTAN_HAS_SKEIN_512)
   if(req.algo_name() == "Skein-512")
      {
      return std::unique_ptr<HashFunction>(
         new Skein_512(req.arg_as_integer(0, 512), req.arg(1, "")));
      }
#endif

#if defined(BOTAN_HAS_BLAKE2B)
   if(req.algo_name() == "Blake2b")
      {
      return std::unique_ptr<HashFunction>(
         new Blake2b(req.arg_as_integer(0, 512)));
   }
#endif

#if defined(BOTAN_HAS_KECCAK)
   if(req.algo_name() == "Keccak-1600")
      {
      return std::unique_ptr<HashFunction>(
         new Keccak_1600(req.arg_as_integer(0, 512)));
      }
#endif

#if defined(BOTAN_HAS_SHA3)
   if(req.algo_name() == "SHA-3")
      {
      return std::unique_ptr<HashFunction>(
         new SHA_3(req.arg_as_integer(0, 512)));
      }
#endif

#if defined(BOTAN_HAS_SHAKE)
   if(req.algo_name() == "SHAKE-128")
      {
      return std::unique_ptr<HashFunction>(new SHAKE_128(req.arg_as_integer(0, 128)));
      }
   if(req.algo_name() == "SHAKE-256")
      {
      return std::unique_ptr<HashFunction>(new SHAKE_256(req.arg_as_integer(0, 256)));
      }
#endif

#if defined(BOTAN_HAS_STREEBOG)
   if(algo_spec == "Streebog-256")
      {
      return std::unique_ptr<HashFunction>(new Streebog_256);
      }
   if(algo_spec == "Streebog-512")
      {
      return std::unique_ptr<HashFunction>(new Streebog_512);
      }
#endif

#if defined(BOTAN_HAS_SM3)
   if(algo_spec == "SM3")
      {
      return std::unique_ptr<HashFunction>(new SM3);
      }
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
   if(req.algo_name() == "Whirlpool")
      {
      return std::unique_ptr<HashFunction>(new Whirlpool);
      }
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)
   if(req.algo_name() == "Parallel")
      {
      std::vector<std::unique_ptr<HashFunction>> hashes;

      for(size_t i = 0; i != req.arg_count(); ++i)
         {
         auto h = HashFunction::create(req.arg(i));
         if(!h)
            {
            return nullptr;
            }
         hashes.push_back(std::move(h));
         }

      return std::unique_ptr<HashFunction>(new Parallel(hashes));
      }
#endif

#if defined(BOTAN_HAS_COMB4P)
   if(req.algo_name() == "Comb4P" && req.arg_count() == 2)
      {
      std::unique_ptr<HashFunction> h1(HashFunction::create(req.arg(0)));
      std::unique_ptr<HashFunction> h2(HashFunction::create(req.arg(1)));

      if(h1 && h2)
         return std::unique_ptr<HashFunction>(new Comb4P(h1.release(), h2.release()));
      }
#endif


   return nullptr;
   }

//static
std::unique_ptr<HashFunction>
HashFunction::create_or_throw(const std::string& algo,
                              const std::string& provider)
   {
   if(auto hash = HashFunction::create(algo, provider))
      {
      return hash;
      }
   throw Lookup_Error("Hash", algo, provider);
   }

std::vector<std::string> HashFunction::providers(const std::string& algo_spec)
   {
   return probe_providers_of<HashFunction>(algo_spec, {"base", "bearssl", "openssl"});
   }

}

/*
* Hex Encoding and Decoding
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

void hex_encode(char output[],
                const uint8_t input[],
                size_t input_length,
                bool uppercase)
   {
   static const uint8_t BIN_TO_HEX_UPPER[16] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'A', 'B', 'C', 'D', 'E', 'F' };

   static const uint8_t BIN_TO_HEX_LOWER[16] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f' };

   const uint8_t* tbl = uppercase ? BIN_TO_HEX_UPPER : BIN_TO_HEX_LOWER;

   for(size_t i = 0; i != input_length; ++i)
      {
      uint8_t x = input[i];
      output[2*i  ] = tbl[(x >> 4) & 0x0F];
      output[2*i+1] = tbl[(x     ) & 0x0F];
      }
   }

std::string hex_encode(const uint8_t input[],
                       size_t input_length,
                       bool uppercase)
   {
   std::string output(2 * input_length, 0);

   if(input_length)
      hex_encode(&output.front(), input, input_length, uppercase);

   return output;
   }

size_t hex_decode(uint8_t output[],
                  const char input[],
                  size_t input_length,
                  size_t& input_consumed,
                  bool ignore_ws)
   {
   /*
   * Mapping of hex characters to either their binary equivalent
   * or to an error code.
   *  If valid hex (0-9 A-F a-f), the value.
   *  If whitespace, then 0x80
   *  Otherwise 0xFF
   * Warning: this table assumes ASCII character encodings
   */

   static const uint8_t HEX_TO_BIN[256] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
      0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01,
      0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
      0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C,
      0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

   uint8_t* out_ptr = output;
   bool top_nibble = true;

   clear_mem(output, input_length / 2);

   for(size_t i = 0; i != input_length; ++i)
      {
      const uint8_t bin = HEX_TO_BIN[static_cast<uint8_t>(input[i])];

      if(bin >= 0x10)
         {
         if(bin == 0x80 && ignore_ws)
            continue;

         std::string bad_char(1, input[i]);
         if(bad_char == "\t")
           bad_char = "\\t";
         else if(bad_char == "\n")
           bad_char = "\\n";

         throw Invalid_Argument(
           std::string("hex_decode: invalid hex character '") +
           bad_char + "'");
         }

      if(top_nibble)
         *out_ptr |= bin << 4;
      else
         *out_ptr |= bin;

      top_nibble = !top_nibble;
      if(top_nibble)
         ++out_ptr;
      }

   input_consumed = input_length;
   size_t written = (out_ptr - output);

   /*
   * We only got half of a uint8_t at the end; zap the half-written
   * output and mark it as unread
   */
   if(!top_nibble)
      {
      *out_ptr = 0;
      input_consumed -= 1;
      }

   return written;
   }

size_t hex_decode(uint8_t output[],
                  const char input[],
                  size_t input_length,
                  bool ignore_ws)
   {
   size_t consumed = 0;
   size_t written = hex_decode(output, input, input_length,
                               consumed, ignore_ws);

   if(consumed != input_length)
      throw Invalid_Argument("hex_decode: input did not have full bytes");

   return written;
   }

size_t hex_decode(uint8_t output[],
                  const std::string& input,
                  bool ignore_ws)
   {
   return hex_decode(output, input.data(), input.length(), ignore_ws);
   }

secure_vector<uint8_t> hex_decode_locked(const char input[],
                                      size_t input_length,
                                      bool ignore_ws)
   {
   secure_vector<uint8_t> bin(1 + input_length / 2);

   size_t written = hex_decode(bin.data(),
                               input,
                               input_length,
                               ignore_ws);

   bin.resize(written);
   return bin;
   }

secure_vector<uint8_t> hex_decode_locked(const std::string& input,
                                      bool ignore_ws)
   {
   return hex_decode_locked(input.data(), input.size(), ignore_ws);
   }

std::vector<uint8_t> hex_decode(const char input[],
                             size_t input_length,
                             bool ignore_ws)
   {
   std::vector<uint8_t> bin(1 + input_length / 2);

   size_t written = hex_decode(bin.data(),
                               input,
                               input_length,
                               ignore_ws);

   bin.resize(written);
   return bin;
   }

std::vector<uint8_t> hex_decode(const std::string& input,
                             bool ignore_ws)
   {
   return hex_decode(input.data(), input.size(), ignore_ws);
   }

}
/*
* HMAC
* (C) 1999-2007,2014 Jack Lloyd
*     2007 Yves Jerschow
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Update a HMAC Calculation
*/
void HMAC::add_data(const uint8_t input[], size_t length)
   {
   verify_key_set(m_ikey.empty() == false);
   m_hash->update(input, length);
   }

/*
* Finalize a HMAC Calculation
*/
void HMAC::final_result(uint8_t mac[])
   {
   verify_key_set(m_okey.empty() == false);
   m_hash->final(mac);
   m_hash->update(m_okey);
   m_hash->update(mac, output_length());
   m_hash->final(mac);
   m_hash->update(m_ikey);
   }

Key_Length_Specification HMAC::key_spec() const
   {
   // Support very long lengths for things like PBKDF2 and the TLS PRF
   return Key_Length_Specification(0, 4096);
   }

/*
* HMAC Key Schedule
*/
void HMAC::key_schedule(const uint8_t key[], size_t length)
   {
   m_hash->clear();

   m_ikey.resize(m_hash->hash_block_size());
   m_okey.resize(m_hash->hash_block_size());

   const uint8_t ipad = 0x36;
   const uint8_t opad = 0x5C;

   std::fill(m_ikey.begin(), m_ikey.end(), ipad);
   std::fill(m_okey.begin(), m_okey.end(), opad);

   if(length > m_hash->hash_block_size())
      {
      secure_vector<uint8_t> hmac_key = m_hash->process(key, length);
      xor_buf(m_ikey, hmac_key, hmac_key.size());
      xor_buf(m_okey, hmac_key, hmac_key.size());
      }
   else
      {
      xor_buf(m_ikey, key, length);
      xor_buf(m_okey, key, length);
      }

   m_hash->update(m_ikey);
   }

/*
* Clear memory of sensitive data
*/
void HMAC::clear()
   {
   m_hash->clear();
   zap(m_ikey);
   zap(m_okey);
   }

/*
* Return the name of this type
*/
std::string HMAC::name() const
   {
   return "HMAC(" + m_hash->name() + ")";
   }

/*
* Return a clone of this object
*/
MessageAuthenticationCode* HMAC::clone() const
   {
   return new HMAC(m_hash->clone());
   }

/*
* HMAC Constructor
*/
HMAC::HMAC(HashFunction* hash) : m_hash(hash)
   {
   if(m_hash->hash_block_size() == 0)
      throw Invalid_Argument("HMAC cannot be used with " + m_hash->name());
   }

}
/*
* HOTP
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

HOTP::HOTP(const SymmetricKey& key, const std::string& hash_algo, size_t digits)
   {
   if(digits == 6)
      m_digit_mod = 1000000;
   else if(digits == 7)
      m_digit_mod = 10000000;
   else if(digits == 8)
      m_digit_mod = 100000000;
   else
      throw Invalid_Argument("Invalid HOTP digits");

   /*
   RFC 4228 only supports SHA-1 but TOTP allows SHA-256 and SHA-512
   and some HOTP libs support one or both as extensions
   */
   if(hash_algo == "SHA-1")
      m_mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-1)");
   else if(hash_algo == "SHA-256")
      m_mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   else if(hash_algo == "SHA-512")
      m_mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");
   else
      throw Invalid_Argument("Unsupported HOTP hash function");

   m_mac->set_key(key);
   }

uint32_t HOTP::generate_hotp(uint64_t counter)
   {
   uint8_t counter8[8] = { 0 };
   store_be(counter, counter8);
   m_mac->update(counter8, sizeof(counter8));
   const secure_vector<uint8_t> mac = m_mac->final();

   const size_t offset = mac[mac.size()-1] & 0x0F;
   const uint32_t code = load_be<uint32_t>(mac.data() + offset, 0) & 0x7FFFFFFF;
   return code % m_digit_mod;
   }

std::pair<bool,uint64_t> HOTP::verify_hotp(uint32_t otp, uint64_t starting_counter, size_t resync_range)
   {
   for(size_t i = 0; i <= resync_range; ++i)
      {
      if(generate_hotp(starting_counter + i) == otp)
         return std::make_pair(true, starting_counter + i + 1);
      }
   return std::make_pair(false, starting_counter);
   }

}

/*
* TOTP
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

TOTP::TOTP(const SymmetricKey& key, const std::string& hash_algo,
           size_t digits, size_t time_step)
   : m_hotp(key, hash_algo, digits)
   , m_time_step(time_step)
   , m_unix_epoch(calendar_point(1970, 1, 1, 0, 0, 0).to_std_timepoint())
   {
   /*
   * Technically any time step except 0 is valid, but 30 is typical
   * and over 5 minutes seems unlikely.
   */
   if(m_time_step == 0 || m_time_step > 300)
      throw Invalid_Argument("Invalid TOTP time step");
   }

uint32_t TOTP::generate_totp(std::chrono::system_clock::time_point current_time)
   {
   const uint64_t unix_time =
      std::chrono::duration_cast<std::chrono::seconds>(current_time - m_unix_epoch).count();
   return this->generate_totp(unix_time);
   }

uint32_t TOTP::generate_totp(uint64_t unix_time)
   {
   return m_hotp.generate_hotp(unix_time / m_time_step);
   }

bool TOTP::verify_totp(uint32_t otp, std::chrono::system_clock::time_point current_time,
                       size_t clock_drift_accepted)
   {
   const uint64_t unix_time =
      std::chrono::duration_cast<std::chrono::seconds>(current_time - m_unix_epoch).count();
   return verify_totp(otp, unix_time, clock_drift_accepted);
   }

bool TOTP::verify_totp(uint32_t otp, uint64_t unix_time,
                       size_t clock_drift_accepted)
   {
   uint64_t t = unix_time / m_time_step;

   for(size_t i = 0; i <= clock_drift_accepted; ++i)
      {
      if(m_hotp.generate_hotp(t-i) == otp)
         {
         return true;
         }
      }

   return false;
   }

}
/*
* KDF Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_HKDF)
#endif

#if defined(BOTAN_HAS_KDF1)
#endif

#if defined(BOTAN_HAS_KDF2)
#endif

#if defined(BOTAN_HAS_KDF1_18033)
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF) || defined(BOTAN_HAS_TLS_V12_PRF)
#endif

#if defined(BOTAN_HAS_X942_PRF)
#endif

#if defined(BOTAN_HAS_SP800_108)
#endif

#if defined(BOTAN_HAS_SP800_56A)
#endif

#if defined(BOTAN_HAS_SP800_56C)
#endif

namespace Botan {

namespace {

template<typename KDF_Type>
std::unique_ptr<KDF>
kdf_create_mac_or_hash(const std::string& nm)
   {
   if(auto mac = MessageAuthenticationCode::create(nm))
      return std::unique_ptr<KDF>(new KDF_Type(mac.release()));

   if(auto mac = MessageAuthenticationCode::create("HMAC(" + nm + ")"))
      return std::unique_ptr<KDF>(new KDF_Type(mac.release()));

   return nullptr;
   }

}

std::unique_ptr<KDF> KDF::create(const std::string& algo_spec,
                                 const std::string& provider)
   {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_HKDF)
   if(req.algo_name() == "HKDF" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<HKDF>(req.arg(0));
         }
      }

   if(req.algo_name() == "HKDF-Extract" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<HKDF_Extract>(req.arg(0));
         }
      }

   if(req.algo_name() == "HKDF-Expand" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<HKDF_Expand>(req.arg(0));
         }
      }
#endif

#if defined(BOTAN_HAS_KDF2)
   if(req.algo_name() == "KDF2" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            return std::unique_ptr<KDF>(new KDF2(hash.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_KDF1_18033)
   if(req.algo_name() == "KDF1-18033" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            return std::unique_ptr<KDF>(new KDF1_18033(hash.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_KDF1)
   if(req.algo_name() == "KDF1" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            return std::unique_ptr<KDF>(new KDF1(hash.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF)
   if(req.algo_name() == "TLS-PRF" && req.arg_count() == 0)
      {
      if(provider.empty() || provider == "base")
         {
         return std::unique_ptr<KDF>(new TLS_PRF);
         }
      }
#endif

#if defined(BOTAN_HAS_TLS_V12_PRF)
   if(req.algo_name() == "TLS-12-PRF" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<TLS_12_PRF>(req.arg(0));
         }
      }
#endif

#if defined(BOTAN_HAS_X942_PRF)
   if(req.algo_name() == "X9.42-PRF" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return std::unique_ptr<KDF>(new X942_PRF(req.arg(0)));
         }
      }
#endif

#if defined(BOTAN_HAS_SP800_108)
   if(req.algo_name() == "SP800-108-Counter" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<SP800_108_Counter>(req.arg(0));
         }
      }

   if(req.algo_name() == "SP800-108-Feedback" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<SP800_108_Feedback>(req.arg(0));
         }
      }

   if(req.algo_name() == "SP800-108-Pipeline" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<SP800_108_Pipeline>(req.arg(0));
         }
      }
#endif

#if defined(BOTAN_HAS_SP800_56A)
   if(req.algo_name() == "SP800-56A" && req.arg_count() == 1)
      {
      if(auto hash = HashFunction::create(req.arg(0)))
         return std::unique_ptr<KDF>(new SP800_56A_Hash(hash.release()));
      if(auto mac = MessageAuthenticationCode::create(req.arg(0)))
         return std::unique_ptr<KDF>(new SP800_56A_HMAC(mac.release()));
      }
#endif

#if defined(BOTAN_HAS_SP800_56C)
   if(req.algo_name() == "SP800-56C" && req.arg_count() == 1)
      {
      std::unique_ptr<KDF> exp(kdf_create_mac_or_hash<SP800_108_Feedback>(req.arg(0)));
      if(exp)
         {
         if(auto mac = MessageAuthenticationCode::create(req.arg(0)))
            return std::unique_ptr<KDF>(new SP800_56C(mac.release(), exp.release()));

         if(auto mac = MessageAuthenticationCode::create("HMAC(" + req.arg(0) + ")"))
            return std::unique_ptr<KDF>(new SP800_56C(mac.release(), exp.release()));
         }
      }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
   }

//static
std::unique_ptr<KDF>
KDF::create_or_throw(const std::string& algo,
                             const std::string& provider)
   {
   if(auto kdf = KDF::create(algo, provider))
      {
      return kdf;
      }
   throw Lookup_Error("KDF", algo, provider);
   }

std::vector<std::string> KDF::providers(const std::string& algo_spec)
   {
   return probe_providers_of<KDF>(algo_spec, { "base" });
   }

KDF* get_kdf(const std::string& algo_spec)
   {
   SCAN_Name request(algo_spec);

   if(request.algo_name() == "Raw")
      return nullptr; // No KDF

   //return KDF::create_or_throw(algo_spec).release();
   auto kdf = KDF::create(algo_spec);
   if(!kdf)
      throw Algorithm_Not_Found(algo_spec);
   return kdf.release();
   }

}
/*
* Message Authentication Code base class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_CBC_MAC)
#endif

#if defined(BOTAN_HAS_CMAC)
#endif

#if defined(BOTAN_HAS_GMAC)
#endif

#if defined(BOTAN_HAS_HMAC)
#endif

#if defined(BOTAN_HAS_POLY1305)
#endif

#if defined(BOTAN_HAS_SIPHASH)
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
#endif

namespace Botan {

std::unique_ptr<MessageAuthenticationCode>
MessageAuthenticationCode::create(const std::string& algo_spec,
                                  const std::string& provider)
   {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_GMAC)
   if(req.algo_name() == "GMAC" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         if(auto bc = BlockCipher::create(req.arg(0)))
            return std::unique_ptr<MessageAuthenticationCode>(new GMAC(bc.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_HMAC)
   if(req.algo_name() == "HMAC" && req.arg_count() == 1)
      {
      // TODO OpenSSL
      if(provider.empty() || provider == "base")
         {
         if(auto h = HashFunction::create(req.arg(0)))
            return std::unique_ptr<MessageAuthenticationCode>(new HMAC(h.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_POLY1305)
   if(req.algo_name() == "Poly1305" && req.arg_count() == 0)
      {
      if(provider.empty() || provider == "base")
         return std::unique_ptr<MessageAuthenticationCode>(new Poly1305);
      }
#endif

#if defined(BOTAN_HAS_SIPHASH)
   if(req.algo_name() == "SipHash")
      {
      if(provider.empty() || provider == "base")
         {
         return std::unique_ptr<MessageAuthenticationCode>(
            new SipHash(req.arg_as_integer(0, 2), req.arg_as_integer(1, 4)));
         }
      }
#endif

#if defined(BOTAN_HAS_CMAC)
   if((req.algo_name() == "CMAC" || req.algo_name() == "OMAC") && req.arg_count() == 1)
      {
      // TODO: OpenSSL CMAC
      if(provider.empty() || provider == "base")
         {
         if(auto bc = BlockCipher::create(req.arg(0)))
            return std::unique_ptr<MessageAuthenticationCode>(new CMAC(bc.release()));
         }
      }
#endif


#if defined(BOTAN_HAS_CBC_MAC)
   if(req.algo_name() == "CBC-MAC" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         if(auto bc = BlockCipher::create(req.arg(0)))
            return std::unique_ptr<MessageAuthenticationCode>(new CBC_MAC(bc.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
   if(req.algo_name() == "X9.19-MAC")
      {
      if(provider.empty() || provider == "base")
         {
         return std::unique_ptr<MessageAuthenticationCode>(new ANSI_X919_MAC);
         }
      }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
   }

std::vector<std::string>
MessageAuthenticationCode::providers(const std::string& algo_spec)
   {
   return probe_providers_of<MessageAuthenticationCode>(algo_spec, {"base", "openssl"});
   }

//static
std::unique_ptr<MessageAuthenticationCode>
MessageAuthenticationCode::create_or_throw(const std::string& algo,
                                           const std::string& provider)
   {
   if(auto mac = MessageAuthenticationCode::create(algo, provider))
      {
      return mac;
      }
   throw Lookup_Error("MAC", algo, provider);
   }

/*
* Default (deterministic) MAC verification operation
*/
bool MessageAuthenticationCode::verify_mac(const uint8_t mac[], size_t length)
   {
   secure_vector<uint8_t> our_mac = final();

   if(our_mac.size() != length)
      return false;

   return constant_time_compare(our_mac.data(), mac, length);
   }

}
/*
* Merkle-Damgard Hash Function
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* MDx_HashFunction Constructor
*/
MDx_HashFunction::MDx_HashFunction(size_t block_len,
                                   bool byte_end,
                                   bool bit_end,
                                   size_t cnt_size) :
   m_buffer(block_len),
   m_count(0),
   m_position(0),
   BIG_BYTE_ENDIAN(byte_end),
   BIG_BIT_ENDIAN(bit_end),
   COUNT_SIZE(cnt_size)
   {
   }

/*
* Clear memory of sensitive data
*/
void MDx_HashFunction::clear()
   {
   zeroise(m_buffer);
   m_count = m_position = 0;
   }

/*
* Update the hash
*/
void MDx_HashFunction::add_data(const uint8_t input[], size_t length)
   {
   m_count += length;

   if(m_position)
      {
      buffer_insert(m_buffer, m_position, input, length);

      if(m_position + length >= m_buffer.size())
         {
         compress_n(m_buffer.data(), 1);
         input += (m_buffer.size() - m_position);
         length -= (m_buffer.size() - m_position);
         m_position = 0;
         }
      }

   const size_t full_blocks = length / m_buffer.size();
   const size_t remaining   = length % m_buffer.size();

   if(full_blocks)
      compress_n(input, full_blocks);

   buffer_insert(m_buffer, m_position, input + full_blocks * m_buffer.size(), remaining);
   m_position += remaining;
   }

/*
* Finalize a hash
*/
void MDx_HashFunction::final_result(uint8_t output[])
   {
   m_buffer[m_position] = (BIG_BIT_ENDIAN ? 0x80 : 0x01);
   for(size_t i = m_position+1; i != m_buffer.size(); ++i)
      m_buffer[i] = 0;

   if(m_position >= m_buffer.size() - COUNT_SIZE)
      {
      compress_n(m_buffer.data(), 1);
      zeroise(m_buffer);
      }

   write_count(&m_buffer[m_buffer.size() - COUNT_SIZE]);

   compress_n(m_buffer.data(), 1);
   copy_out(output);
   clear();
   }

/*
* Write the count bits to the buffer
*/
void MDx_HashFunction::write_count(uint8_t out[])
   {
   if(COUNT_SIZE < 8)
      throw Invalid_State("MDx_HashFunction::write_count: COUNT_SIZE < 8");
   if(COUNT_SIZE >= output_length() || COUNT_SIZE >= hash_block_size())
      throw Invalid_Argument("MDx_HashFunction: COUNT_SIZE is too big");

   const uint64_t bit_count = m_count * 8;

   if(BIG_BYTE_ENDIAN)
      store_be(bit_count, out + COUNT_SIZE - 8);
   else
      store_le(bit_count, out + COUNT_SIZE - 8);
   }

}
/*
* CBC Padding Methods
* (C) 1999-2007,2013 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/**
* Get a block cipher padding method by name
*/
BlockCipherModePaddingMethod* get_bc_pad(const std::string& algo_spec)
   {
   if(algo_spec == "NoPadding")
      return new Null_Padding;

   if(algo_spec == "PKCS7")
      return new PKCS7_Padding;

   if(algo_spec == "OneAndZeros")
      return new OneAndZeros_Padding;

   if(algo_spec == "X9.23")
      return new ANSI_X923_Padding;

   if(algo_spec == "ESP")
      return new ESP_Padding;

   return nullptr;
   }

/*
* Pad with PKCS #7 Method
*/
void PKCS7_Padding::add_padding(secure_vector<uint8_t>& buffer,
                                size_t last_byte_pos,
                                size_t block_size) const
   {
   const uint8_t pad_value = static_cast<uint8_t>(block_size - last_byte_pos);

   for(size_t i = 0; i != pad_value; ++i)
      buffer.push_back(pad_value);
   }

/*
* Unpad with PKCS #7 Method
*/
size_t PKCS7_Padding::unpad(const uint8_t block[], size_t size) const
   {
   CT::poison(block,size);
   size_t bad_input = 0;
   const uint8_t last_byte = block[size-1];

   bad_input |= CT::expand_mask<size_t>(last_byte > size);

   size_t pad_pos = size - last_byte;
   size_t i = size - 2;
   while(i)
      {
      bad_input |= (~CT::is_equal(block[i],last_byte)) & CT::expand_mask<uint8_t>(i >= pad_pos);
      --i;
      }

   CT::conditional_copy_mem(bad_input,&pad_pos,&size,&pad_pos,1);
   CT::unpoison(block,size);
   CT::unpoison(pad_pos);
   return pad_pos;
   }

/*
* Pad with ANSI X9.23 Method
*/
void ANSI_X923_Padding::add_padding(secure_vector<uint8_t>& buffer,
                                    size_t last_byte_pos,
                                    size_t block_size) const
   {
   const uint8_t pad_value = static_cast<uint8_t>(block_size - last_byte_pos);

   for(size_t i = last_byte_pos; i < block_size-1; ++i)
      {
      buffer.push_back(0);
      }
   buffer.push_back(pad_value);
   }

/*
* Unpad with ANSI X9.23 Method
*/
size_t ANSI_X923_Padding::unpad(const uint8_t block[], size_t size) const
   {
   CT::poison(block,size);
   size_t bad_input = 0;
   const size_t last_byte = block[size-1];

   bad_input |= CT::expand_mask<size_t>(last_byte > size);

   size_t pad_pos = size - last_byte;
   size_t i = size - 2;
   while(i)
      {
      bad_input |= (~CT::is_zero(block[i])) & CT::expand_mask<uint8_t>(i >= pad_pos);
      --i;
      }
   CT::conditional_copy_mem(bad_input,&pad_pos,&size,&pad_pos,1);
   CT::unpoison(block,size);
   CT::unpoison(pad_pos);
   return pad_pos;
   }

/*
* Pad with One and Zeros Method
*/
void OneAndZeros_Padding::add_padding(secure_vector<uint8_t>& buffer,
                                      size_t last_byte_pos,
                                      size_t block_size) const
   {
   buffer.push_back(0x80);

   for(size_t i = last_byte_pos + 1; i % block_size; ++i)
      buffer.push_back(0x00);
   }

/*
* Unpad with One and Zeros Method
*/
size_t OneAndZeros_Padding::unpad(const uint8_t block[], size_t size) const
   {
   CT::poison(block, size);
   uint8_t bad_input = 0;
   uint8_t seen_one = 0;
   size_t pad_pos = size - 1;
   size_t i = size;

   while(i)
      {
      seen_one |= CT::is_equal<uint8_t>(block[i-1],0x80);
      pad_pos -= CT::select<uint8_t>(~seen_one, 1, 0);
      bad_input |= ~CT::is_zero<uint8_t>(block[i-1]) & ~seen_one;
      i--;
      }
   bad_input |= ~seen_one;

   CT::conditional_copy_mem(size_t(bad_input),&pad_pos,&size,&pad_pos,1);
   CT::unpoison(block, size);
   CT::unpoison(pad_pos);

   return pad_pos;
   }

/*
* Pad with ESP Padding Method
*/
void ESP_Padding::add_padding(secure_vector<uint8_t>& buffer,
                              size_t last_byte_pos,
                              size_t block_size) const
   {
   uint8_t pad_value = 0x01;

   for(size_t i = last_byte_pos; i < block_size; ++i)
      {
      buffer.push_back(pad_value++);
      }
   }

/*
* Unpad with ESP Padding Method
*/
size_t ESP_Padding::unpad(const uint8_t block[], size_t size) const
   {
   CT::poison(block,size);

   const size_t last_byte = block[size-1];
   size_t bad_input = 0;
   bad_input |= CT::expand_mask<size_t>(last_byte > size);

   size_t pad_pos = size - last_byte;
   size_t i = size - 1;
   while(i)
      {
      bad_input |= ~CT::is_equal<uint8_t>(size_t(block[i-1]),size_t(block[i])-1) & CT::expand_mask<uint8_t>(i > pad_pos);
      --i;
      }
   CT::conditional_copy_mem(bad_input,&pad_pos,&size,&pad_pos,1);
   CT::unpoison(block, size);
   CT::unpoison(pad_pos);
   return pad_pos;
   }


}
/*
* Cipher Modes
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_BLOCK_CIPHER)
#endif

#if defined(BOTAN_HAS_AEAD_MODES)
#endif

#if defined(BOTAN_HAS_MODE_CBC)
#endif

#if defined(BOTAN_HAS_MODE_CFB)
#endif

#if defined(BOTAN_HAS_MODE_XTS)
#endif

#if defined(BOTAN_HAS_OPENSSL)
#endif

namespace Botan {

Cipher_Mode* get_cipher_mode(const std::string& algo, Cipher_Dir direction,
                             const std::string& provider)
   {
#if defined(BOTAN_HAS_OPENSSL)
   if(provider.empty() || provider == "openssl")
      {
      if(Cipher_Mode* bc = make_openssl_cipher_mode(algo, direction))
         return bc;

      if(!provider.empty())
         return nullptr;
      }
#endif

   if(auto sc = StreamCipher::create(algo))
      {
      return new Stream_Cipher_Mode(sc.release());
      }

#if defined(BOTAN_HAS_AEAD_MODES)
   if(auto aead = get_aead(algo, direction))
      {
      return aead;
      }
#endif

   if(algo.find('/') != std::string::npos)
      {
      const std::vector<std::string> algo_parts = split_on(algo, '/');
      const std::string cipher_name = algo_parts[0];
      const std::vector<std::string> mode_info = parse_algorithm_name(algo_parts[1]);

      if(mode_info.empty())
         return nullptr;

      std::ostringstream alg_args;

      alg_args << '(' << cipher_name;
      for(size_t i = 1; i < mode_info.size(); ++i)
         alg_args << ',' << mode_info[i];
      for(size_t i = 2; i < algo_parts.size(); ++i)
         alg_args << ',' << algo_parts[i];
      alg_args << ')';

      const std::string mode_name = mode_info[0] + alg_args.str();
      return get_cipher_mode(mode_name, direction, provider);
      }

#if defined(BOTAN_HAS_BLOCK_CIPHER)

   SCAN_Name spec(algo);

   if(spec.arg_count() == 0)
      {
      return nullptr;
      }

   std::unique_ptr<BlockCipher> bc(BlockCipher::create(spec.arg(0), provider));

   if(!bc)
      {
      return nullptr;
      }

#if defined(BOTAN_HAS_MODE_CBC)
   if(spec.algo_name() == "CBC")
      {
      const std::string padding = spec.arg(1, "PKCS7");

      if(padding == "CTS")
         {
         if(direction == ENCRYPTION)
            return new CTS_Encryption(bc.release());
         else
            return new CTS_Decryption(bc.release());
         }
      else
         {
         std::unique_ptr<BlockCipherModePaddingMethod> pad(get_bc_pad(padding));

         if(pad)
            {
            if(direction == ENCRYPTION)
               return new CBC_Encryption(bc.release(), pad.release());
            else
               return new CBC_Decryption(bc.release(), pad.release());
            }
         }
      }
#endif

#if defined(BOTAN_HAS_MODE_XTS)
   if(spec.algo_name() == "XTS")
      {
      if(direction == ENCRYPTION)
         return new XTS_Encryption(bc.release());
      else
         return new XTS_Decryption(bc.release());
      }
#endif

#if defined(BOTAN_HAS_MODE_CFB)
   if(spec.algo_name() == "CFB")
      {
      const size_t feedback_bits = spec.arg_as_integer(1, 8*bc->block_size());
      if(direction == ENCRYPTION)
         return new CFB_Encryption(bc.release(), feedback_bits);
      else
         return new CFB_Decryption(bc.release(), feedback_bits);
      }
#endif

#endif

   return nullptr;
   }

//static
std::vector<std::string> Cipher_Mode::providers(const std::string& algo_spec)
   {
   const std::vector<std::string>& possible = { "base", "openssl" };
   std::vector<std::string> providers;
   for(auto&& prov : possible)
      {
      std::unique_ptr<Cipher_Mode> mode(get_cipher_mode(algo_spec, ENCRYPTION, prov));
      if(mode)
         {
         providers.push_back(prov); // available
         }
      }
   return providers;
   }

}
/*
* Comba Multiplication and Squaring
*
* This file was automatically generated by ./src/scripts/comba.py on 2016-01-01
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Comba 4x4 Squaring
*/
void bigint_comba_sqr4(word z[8], const word x[4])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd  (&w2, &w1, &w0, x[ 0], x[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
   z[ 1] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
   word3_muladd  (&w1, &w0, &w2, x[ 1], x[ 1]);
   z[ 2] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
   z[ 3] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
   word3_muladd  (&w0, &w2, &w1, x[ 2], x[ 2]);
   z[ 4] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
   z[ 5] = w2; w2 = 0;

   word3_muladd  (&w2, &w1, &w0, x[ 3], x[ 3]);
   z[ 6] = w0;
   z[ 7] = w1;
   }

/*
* Comba 4x4 Multiplication
*/
void bigint_comba_mul4(word z[8], const word x[4], const word y[4])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
   z[ 1] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
   z[ 2] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
   z[ 3] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
   z[ 4] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
   z[ 5] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
   z[ 6] = w0;
   z[ 7] = w1;
   }

/*
* Comba 6x6 Squaring
*/
void bigint_comba_sqr6(word z[12], const word x[6])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd  (&w2, &w1, &w0, x[ 0], x[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
   z[ 1] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
   word3_muladd  (&w1, &w0, &w2, x[ 1], x[ 1]);
   z[ 2] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
   z[ 3] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 4]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
   word3_muladd  (&w0, &w2, &w1, x[ 2], x[ 2]);
   z[ 4] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 5]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 4]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
   z[ 5] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 5]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 4]);
   word3_muladd  (&w2, &w1, &w0, x[ 3], x[ 3]);
   z[ 6] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 5]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 4]);
   z[ 7] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 5]);
   word3_muladd  (&w1, &w0, &w2, x[ 4], x[ 4]);
   z[ 8] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 5]);
   z[ 9] = w0; w0 = 0;

   word3_muladd  (&w0, &w2, &w1, x[ 5], x[ 5]);
   z[10] = w1;
   z[11] = w2;
   }

/*
* Comba 6x6 Multiplication
*/
void bigint_comba_mul6(word z[12], const word x[6], const word y[6])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
   z[ 1] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
   z[ 2] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
   z[ 3] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 0]);
   z[ 4] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 0]);
   z[ 5] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 1]);
   z[ 6] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 2]);
   z[ 7] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 3]);
   z[ 8] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 4]);
   z[ 9] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 5]);
   z[10] = w1;
   z[11] = w2;
   }

/*
* Comba 8x8 Squaring
*/
void bigint_comba_sqr8(word z[16], const word x[8])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd  (&w2, &w1, &w0, x[ 0], x[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
   z[ 1] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
   word3_muladd  (&w1, &w0, &w2, x[ 1], x[ 1]);
   z[ 2] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
   z[ 3] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 4]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
   word3_muladd  (&w0, &w2, &w1, x[ 2], x[ 2]);
   z[ 4] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 5]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 4]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
   z[ 5] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 6]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 5]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 4]);
   word3_muladd  (&w2, &w1, &w0, x[ 3], x[ 3]);
   z[ 6] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 7]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 6]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 5]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 4]);
   z[ 7] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 7]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 6]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 5]);
   word3_muladd  (&w1, &w0, &w2, x[ 4], x[ 4]);
   z[ 8] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 7]);
   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[ 6]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 5]);
   z[ 9] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 7]);
   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[ 6]);
   word3_muladd  (&w0, &w2, &w1, x[ 5], x[ 5]);
   z[10] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 4], x[ 7]);
   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[ 6]);
   z[11] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 5], x[ 7]);
   word3_muladd  (&w2, &w1, &w0, x[ 6], x[ 6]);
   z[12] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 6], x[ 7]);
   z[13] = w1; w1 = 0;

   word3_muladd  (&w1, &w0, &w2, x[ 7], x[ 7]);
   z[14] = w2;
   z[15] = w0;
   }

/*
* Comba 8x8 Multiplication
*/
void bigint_comba_mul8(word z[16], const word x[8], const word y[8])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
   z[ 1] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
   z[ 2] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
   z[ 3] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 0]);
   z[ 4] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 0]);
   z[ 5] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 0]);
   z[ 6] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 0]);
   z[ 7] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 1]);
   z[ 8] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 2]);
   z[ 9] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 3]);
   z[10] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 4]);
   z[11] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 5]);
   z[12] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 6]);
   z[13] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 7]);
   z[14] = w2;
   z[15] = w0;
   }

/*
* Comba 9x9 Squaring
*/
void bigint_comba_sqr9(word z[18], const word x[9])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd  (&w2, &w1, &w0, x[ 0], x[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
   z[ 1] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
   word3_muladd  (&w1, &w0, &w2, x[ 1], x[ 1]);
   z[ 2] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
   z[ 3] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 4]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
   word3_muladd  (&w0, &w2, &w1, x[ 2], x[ 2]);
   z[ 4] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 5]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 4]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
   z[ 5] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 6]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 5]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 4]);
   word3_muladd  (&w2, &w1, &w0, x[ 3], x[ 3]);
   z[ 6] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 7]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 6]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 5]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 4]);
   z[ 7] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 8]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 7]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 6]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 5]);
   word3_muladd  (&w1, &w0, &w2, x[ 4], x[ 4]);
   z[ 8] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 8]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 7]);
   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[ 6]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 5]);
   z[ 9] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 8]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 7]);
   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[ 6]);
   word3_muladd  (&w0, &w2, &w1, x[ 5], x[ 5]);
   z[10] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 8]);
   word3_muladd_2(&w1, &w0, &w2, x[ 4], x[ 7]);
   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[ 6]);
   z[11] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 8]);
   word3_muladd_2(&w2, &w1, &w0, x[ 5], x[ 7]);
   word3_muladd  (&w2, &w1, &w0, x[ 6], x[ 6]);
   z[12] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 5], x[ 8]);
   word3_muladd_2(&w0, &w2, &w1, x[ 6], x[ 7]);
   z[13] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 6], x[ 8]);
   word3_muladd  (&w1, &w0, &w2, x[ 7], x[ 7]);
   z[14] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 7], x[ 8]);
   z[15] = w0; w0 = 0;

   word3_muladd  (&w0, &w2, &w1, x[ 8], x[ 8]);
   z[16] = w1;
   z[17] = w2;
   }

/*
* Comba 9x9 Multiplication
*/
void bigint_comba_mul9(word z[18], const word x[9], const word y[9])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
   z[ 1] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
   z[ 2] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
   z[ 3] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 0]);
   z[ 4] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 0]);
   z[ 5] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 0]);
   z[ 6] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 0]);
   z[ 7] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 0]);
   z[ 8] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[ 1]);
   z[ 9] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[ 2]);
   z[10] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 3]);
   z[11] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[ 4]);
   z[12] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[ 5]);
   z[13] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 6]);
   z[14] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[ 7]);
   z[15] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 8], y[ 8]);
   z[16] = w1;
   z[17] = w2;
   }

/*
* Comba 16x16 Squaring
*/
void bigint_comba_sqr16(word z[32], const word x[16])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd  (&w2, &w1, &w0, x[ 0], x[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
   z[ 1] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
   word3_muladd  (&w1, &w0, &w2, x[ 1], x[ 1]);
   z[ 2] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
   z[ 3] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 4]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
   word3_muladd  (&w0, &w2, &w1, x[ 2], x[ 2]);
   z[ 4] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 5]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 4]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
   z[ 5] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 6]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 5]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 4]);
   word3_muladd  (&w2, &w1, &w0, x[ 3], x[ 3]);
   z[ 6] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 7]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 6]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 5]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 4]);
   z[ 7] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 8]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 7]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 6]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 5]);
   word3_muladd  (&w1, &w0, &w2, x[ 4], x[ 4]);
   z[ 8] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 9]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 8]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 7]);
   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[ 6]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 5]);
   z[ 9] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[10]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 9]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 8]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 7]);
   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[ 6]);
   word3_muladd  (&w0, &w2, &w1, x[ 5], x[ 5]);
   z[10] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[11]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[10]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 9]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 8]);
   word3_muladd_2(&w1, &w0, &w2, x[ 4], x[ 7]);
   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[ 6]);
   z[11] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[12]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[11]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[10]);
   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[ 9]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 8]);
   word3_muladd_2(&w2, &w1, &w0, x[ 5], x[ 7]);
   word3_muladd  (&w2, &w1, &w0, x[ 6], x[ 6]);
   z[12] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[13]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[12]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[11]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[10]);
   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[ 9]);
   word3_muladd_2(&w0, &w2, &w1, x[ 5], x[ 8]);
   word3_muladd_2(&w0, &w2, &w1, x[ 6], x[ 7]);
   z[13] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[14]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[13]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[12]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[11]);
   word3_muladd_2(&w1, &w0, &w2, x[ 4], x[10]);
   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[ 9]);
   word3_muladd_2(&w1, &w0, &w2, x[ 6], x[ 8]);
   word3_muladd  (&w1, &w0, &w2, x[ 7], x[ 7]);
   z[14] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[15]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[14]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[13]);
   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[12]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[11]);
   word3_muladd_2(&w2, &w1, &w0, x[ 5], x[10]);
   word3_muladd_2(&w2, &w1, &w0, x[ 6], x[ 9]);
   word3_muladd_2(&w2, &w1, &w0, x[ 7], x[ 8]);
   z[15] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[15]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[14]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[13]);
   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[12]);
   word3_muladd_2(&w0, &w2, &w1, x[ 5], x[11]);
   word3_muladd_2(&w0, &w2, &w1, x[ 6], x[10]);
   word3_muladd_2(&w0, &w2, &w1, x[ 7], x[ 9]);
   word3_muladd  (&w0, &w2, &w1, x[ 8], x[ 8]);
   z[16] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[15]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[14]);
   word3_muladd_2(&w1, &w0, &w2, x[ 4], x[13]);
   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[12]);
   word3_muladd_2(&w1, &w0, &w2, x[ 6], x[11]);
   word3_muladd_2(&w1, &w0, &w2, x[ 7], x[10]);
   word3_muladd_2(&w1, &w0, &w2, x[ 8], x[ 9]);
   z[17] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[15]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[14]);
   word3_muladd_2(&w2, &w1, &w0, x[ 5], x[13]);
   word3_muladd_2(&w2, &w1, &w0, x[ 6], x[12]);
   word3_muladd_2(&w2, &w1, &w0, x[ 7], x[11]);
   word3_muladd_2(&w2, &w1, &w0, x[ 8], x[10]);
   word3_muladd  (&w2, &w1, &w0, x[ 9], x[ 9]);
   z[18] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[15]);
   word3_muladd_2(&w0, &w2, &w1, x[ 5], x[14]);
   word3_muladd_2(&w0, &w2, &w1, x[ 6], x[13]);
   word3_muladd_2(&w0, &w2, &w1, x[ 7], x[12]);
   word3_muladd_2(&w0, &w2, &w1, x[ 8], x[11]);
   word3_muladd_2(&w0, &w2, &w1, x[ 9], x[10]);
   z[19] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[15]);
   word3_muladd_2(&w1, &w0, &w2, x[ 6], x[14]);
   word3_muladd_2(&w1, &w0, &w2, x[ 7], x[13]);
   word3_muladd_2(&w1, &w0, &w2, x[ 8], x[12]);
   word3_muladd_2(&w1, &w0, &w2, x[ 9], x[11]);
   word3_muladd  (&w1, &w0, &w2, x[10], x[10]);
   z[20] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 6], x[15]);
   word3_muladd_2(&w2, &w1, &w0, x[ 7], x[14]);
   word3_muladd_2(&w2, &w1, &w0, x[ 8], x[13]);
   word3_muladd_2(&w2, &w1, &w0, x[ 9], x[12]);
   word3_muladd_2(&w2, &w1, &w0, x[10], x[11]);
   z[21] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 7], x[15]);
   word3_muladd_2(&w0, &w2, &w1, x[ 8], x[14]);
   word3_muladd_2(&w0, &w2, &w1, x[ 9], x[13]);
   word3_muladd_2(&w0, &w2, &w1, x[10], x[12]);
   word3_muladd  (&w0, &w2, &w1, x[11], x[11]);
   z[22] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 8], x[15]);
   word3_muladd_2(&w1, &w0, &w2, x[ 9], x[14]);
   word3_muladd_2(&w1, &w0, &w2, x[10], x[13]);
   word3_muladd_2(&w1, &w0, &w2, x[11], x[12]);
   z[23] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 9], x[15]);
   word3_muladd_2(&w2, &w1, &w0, x[10], x[14]);
   word3_muladd_2(&w2, &w1, &w0, x[11], x[13]);
   word3_muladd  (&w2, &w1, &w0, x[12], x[12]);
   z[24] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[10], x[15]);
   word3_muladd_2(&w0, &w2, &w1, x[11], x[14]);
   word3_muladd_2(&w0, &w2, &w1, x[12], x[13]);
   z[25] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[11], x[15]);
   word3_muladd_2(&w1, &w0, &w2, x[12], x[14]);
   word3_muladd  (&w1, &w0, &w2, x[13], x[13]);
   z[26] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[12], x[15]);
   word3_muladd_2(&w2, &w1, &w0, x[13], x[14]);
   z[27] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[13], x[15]);
   word3_muladd  (&w0, &w2, &w1, x[14], x[14]);
   z[28] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[14], x[15]);
   z[29] = w2; w2 = 0;

   word3_muladd  (&w2, &w1, &w0, x[15], x[15]);
   z[30] = w0;
   z[31] = w1;
   }

/*
* Comba 16x16 Multiplication
*/
void bigint_comba_mul16(word z[32], const word x[16], const word y[16])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
   z[ 1] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
   z[ 2] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
   z[ 3] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 0]);
   z[ 4] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 0]);
   z[ 5] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 0]);
   z[ 6] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 0]);
   z[ 7] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 0]);
   z[ 8] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 9]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 9], y[ 0]);
   z[ 9] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[10]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 9]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 9], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[10], y[ 0]);
   z[10] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[11]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[10]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 9]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 9], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[10], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[11], y[ 0]);
   z[11] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[12]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[11]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[10]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 9]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 9], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[10], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[11], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[12], y[ 0]);
   z[12] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[13]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[12]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[11]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[10]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 9]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 9], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[10], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[11], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[12], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[13], y[ 0]);
   z[13] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[14]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[13]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[12]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[11]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[10]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 9]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 9], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[10], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[11], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[12], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[13], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[14], y[ 0]);
   z[14] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[15]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[14]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[13]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[12]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[11]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[10]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 9]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 9], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[10], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[11], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[12], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[13], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[14], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[15], y[ 0]);
   z[15] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 1], y[15]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[14]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[13]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[12]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[11]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[10]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 9]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[ 9], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[10], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[11], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[12], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[13], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[14], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[15], y[ 1]);
   z[16] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 2], y[15]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[14]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[13]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[12]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[11]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[10]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 9]);
   word3_muladd(&w1, &w0, &w2, x[ 9], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[10], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[11], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[12], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[13], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[14], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[15], y[ 2]);
   z[17] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 3], y[15]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[14]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[13]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[12]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[11]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[10]);
   word3_muladd(&w2, &w1, &w0, x[ 9], y[ 9]);
   word3_muladd(&w2, &w1, &w0, x[10], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[11], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[12], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[13], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[14], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[15], y[ 3]);
   z[18] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 4], y[15]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[14]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[13]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[12]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[11]);
   word3_muladd(&w0, &w2, &w1, x[ 9], y[10]);
   word3_muladd(&w0, &w2, &w1, x[10], y[ 9]);
   word3_muladd(&w0, &w2, &w1, x[11], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[12], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[13], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[14], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[15], y[ 4]);
   z[19] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 5], y[15]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[14]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[13]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[12]);
   word3_muladd(&w1, &w0, &w2, x[ 9], y[11]);
   word3_muladd(&w1, &w0, &w2, x[10], y[10]);
   word3_muladd(&w1, &w0, &w2, x[11], y[ 9]);
   word3_muladd(&w1, &w0, &w2, x[12], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[13], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[14], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[15], y[ 5]);
   z[20] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 6], y[15]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[14]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[13]);
   word3_muladd(&w2, &w1, &w0, x[ 9], y[12]);
   word3_muladd(&w2, &w1, &w0, x[10], y[11]);
   word3_muladd(&w2, &w1, &w0, x[11], y[10]);
   word3_muladd(&w2, &w1, &w0, x[12], y[ 9]);
   word3_muladd(&w2, &w1, &w0, x[13], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[14], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[15], y[ 6]);
   z[21] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 7], y[15]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[14]);
   word3_muladd(&w0, &w2, &w1, x[ 9], y[13]);
   word3_muladd(&w0, &w2, &w1, x[10], y[12]);
   word3_muladd(&w0, &w2, &w1, x[11], y[11]);
   word3_muladd(&w0, &w2, &w1, x[12], y[10]);
   word3_muladd(&w0, &w2, &w1, x[13], y[ 9]);
   word3_muladd(&w0, &w2, &w1, x[14], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[15], y[ 7]);
   z[22] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 8], y[15]);
   word3_muladd(&w1, &w0, &w2, x[ 9], y[14]);
   word3_muladd(&w1, &w0, &w2, x[10], y[13]);
   word3_muladd(&w1, &w0, &w2, x[11], y[12]);
   word3_muladd(&w1, &w0, &w2, x[12], y[11]);
   word3_muladd(&w1, &w0, &w2, x[13], y[10]);
   word3_muladd(&w1, &w0, &w2, x[14], y[ 9]);
   word3_muladd(&w1, &w0, &w2, x[15], y[ 8]);
   z[23] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 9], y[15]);
   word3_muladd(&w2, &w1, &w0, x[10], y[14]);
   word3_muladd(&w2, &w1, &w0, x[11], y[13]);
   word3_muladd(&w2, &w1, &w0, x[12], y[12]);
   word3_muladd(&w2, &w1, &w0, x[13], y[11]);
   word3_muladd(&w2, &w1, &w0, x[14], y[10]);
   word3_muladd(&w2, &w1, &w0, x[15], y[ 9]);
   z[24] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[10], y[15]);
   word3_muladd(&w0, &w2, &w1, x[11], y[14]);
   word3_muladd(&w0, &w2, &w1, x[12], y[13]);
   word3_muladd(&w0, &w2, &w1, x[13], y[12]);
   word3_muladd(&w0, &w2, &w1, x[14], y[11]);
   word3_muladd(&w0, &w2, &w1, x[15], y[10]);
   z[25] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[11], y[15]);
   word3_muladd(&w1, &w0, &w2, x[12], y[14]);
   word3_muladd(&w1, &w0, &w2, x[13], y[13]);
   word3_muladd(&w1, &w0, &w2, x[14], y[12]);
   word3_muladd(&w1, &w0, &w2, x[15], y[11]);
   z[26] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[12], y[15]);
   word3_muladd(&w2, &w1, &w0, x[13], y[14]);
   word3_muladd(&w2, &w1, &w0, x[14], y[13]);
   word3_muladd(&w2, &w1, &w0, x[15], y[12]);
   z[27] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[13], y[15]);
   word3_muladd(&w0, &w2, &w1, x[14], y[14]);
   word3_muladd(&w0, &w2, &w1, x[15], y[13]);
   z[28] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[14], y[15]);
   word3_muladd(&w1, &w0, &w2, x[15], y[14]);
   z[29] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[15], y[15]);
   z[30] = w0;
   z[31] = w1;
   }

}
/*
* MPI Add, Subtract, Word Multiply
* (C) 1999-2010,2016 Jack Lloyd
*     2006 Luca Piccarreta
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* If cond == 0, does nothing.
* If cond > 0, swaps x[0:size] with y[0:size]
* Runs in constant time
*/
void bigint_cnd_swap(word cnd, word x[], word y[], size_t size)
   {
   const word mask = CT::expand_mask(cnd);

   for(size_t i = 0; i != size; ++i)
      {
      word a = x[i];
      word b = y[i];
      x[i] = CT::select(mask, b, a);
      y[i] = CT::select(mask, a, b);
      }
   }

/*
* If cond > 0 adds x[0:size] to y[0:size] and returns carry
* Runs in constant time
*/
word bigint_cnd_add(word cnd, word x[], const word y[], size_t size)
   {
   const word mask = CT::expand_mask(cnd);

   word carry = 0;
   for(size_t i = 0; i != size; ++i)
      {
      /*
      Here we are relying on asm version of word_add being
      a single addcl or equivalent. Fix this.
      */
      const word z = word_add(x[i], y[i], &carry);
      x[i] = CT::select(mask, z, x[i]);
      }

   return carry & mask;
   }

/*
* If cond > 0 subs x[0:size] to y[0:size] and returns borrow
* Runs in constant time
*/
word bigint_cnd_sub(word cnd, word x[], const word y[], size_t size)
   {
   const word mask = CT::expand_mask(cnd);

   word carry = 0;
   for(size_t i = 0; i != size; ++i)
      {
      const word z = word_sub(x[i], y[i], &carry);
      x[i] = CT::select(mask, z, x[i]);
      }

   return carry & mask;
   }

void bigint_cnd_abs(word cnd, word x[], size_t size)
   {
   const word mask = CT::expand_mask(cnd);

   word carry = mask & 1;
   for(size_t i = 0; i != size; ++i)
      {
      const word z = word_add(~x[i], 0, &carry);
      x[i] = CT::select(mask, z, x[i]);
      }
   }

/*
* Two Operand Addition, No Carry
*/
word bigint_add2_nc(word x[], size_t x_size, const word y[], size_t y_size)
   {
   word carry = 0;

   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8)
      carry = word8_add2(x + i, y + i, carry);

   for(size_t i = blocks; i != y_size; ++i)
      x[i] = word_add(x[i], y[i], &carry);

   for(size_t i = y_size; i != x_size; ++i)
      x[i] = word_add(x[i], 0, &carry);

   return carry;
   }

/*
* Three Operand Addition, No Carry
*/
word bigint_add3_nc(word z[], const word x[], size_t x_size,
                              const word y[], size_t y_size)
   {
   if(x_size < y_size)
      { return bigint_add3_nc(z, y, y_size, x, x_size); }

   word carry = 0;

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8)
      carry = word8_add3(z + i, x + i, y + i, carry);

   for(size_t i = blocks; i != y_size; ++i)
      z[i] = word_add(x[i], y[i], &carry);

   for(size_t i = y_size; i != x_size; ++i)
      z[i] = word_add(x[i], 0, &carry);

   return carry;
   }

/*
* Two Operand Addition
*/
void bigint_add2(word x[], size_t x_size, const word y[], size_t y_size)
   {
   if(bigint_add2_nc(x, x_size, y, y_size))
      x[x_size] += 1;
   }

/*
* Three Operand Addition
*/
void bigint_add3(word z[], const word x[], size_t x_size,
                           const word y[], size_t y_size)
   {
   z[x_size > y_size ? x_size : y_size] +=
      bigint_add3_nc(z, x, x_size, y, y_size);
   }

/*
* Two Operand Subtraction
*/
word bigint_sub2(word x[], size_t x_size, const word y[], size_t y_size)
   {
   word borrow = 0;

   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8)
      borrow = word8_sub2(x + i, y + i, borrow);

   for(size_t i = blocks; i != y_size; ++i)
      x[i] = word_sub(x[i], y[i], &borrow);

   for(size_t i = y_size; i != x_size; ++i)
      x[i] = word_sub(x[i], 0, &borrow);

   return borrow;
   }

/*
* Two Operand Subtraction x = y - x
*/
void bigint_sub2_rev(word x[],  const word y[], size_t y_size)
   {
   word borrow = 0;

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8)
      borrow = word8_sub2_rev(x + i, y + i, borrow);

   for(size_t i = blocks; i != y_size; ++i)
      x[i] = word_sub(y[i], x[i], &borrow);

   BOTAN_ASSERT(!borrow, "y must be greater than x");
   }

/*
* Three Operand Subtraction
*/
word bigint_sub3(word z[], const word x[], size_t x_size,
                           const word y[], size_t y_size)
   {
   word borrow = 0;

   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8)
      borrow = word8_sub3(z + i, x + i, y + i, borrow);

   for(size_t i = blocks; i != y_size; ++i)
      z[i] = word_sub(x[i], y[i], &borrow);

   for(size_t i = y_size; i != x_size; ++i)
      z[i] = word_sub(x[i], 0, &borrow);

   return borrow;
   }

/*
* Two Operand Linear Multiply
*/
void bigint_linmul2(word x[], size_t x_size, word y)
   {
   const size_t blocks = x_size - (x_size % 8);

   word carry = 0;

   for(size_t i = 0; i != blocks; i += 8)
      carry = word8_linmul2(x + i, y, carry);

   for(size_t i = blocks; i != x_size; ++i)
      x[i] = word_madd2(x[i], y, &carry);

   x[x_size] = carry;
   }

/*
* Three Operand Linear Multiply
*/
void bigint_linmul3(word z[], const word x[], size_t x_size, word y)
   {
   const size_t blocks = x_size - (x_size % 8);

   word carry = 0;

   for(size_t i = 0; i != blocks; i += 8)
      carry = word8_linmul3(z + i, x + i, y, carry);

   for(size_t i = blocks; i != x_size; ++i)
      z[i] = word_madd2(x[i], y, &carry);

   z[x_size] = carry;
   }

/*
* Single Operand Left Shift
*/
void bigint_shl1(word x[], size_t x_size, size_t word_shift, size_t bit_shift)
   {
   if(word_shift)
      {
      copy_mem(x + word_shift, x, x_size);
      clear_mem(x, word_shift);
      }

   if(bit_shift)
      {
      word carry = 0;
      for(size_t j = word_shift; j != x_size + word_shift + 1; ++j)
         {
         word temp = x[j];
         x[j] = (temp << bit_shift) | carry;
         carry = (temp >> (MP_WORD_BITS - bit_shift));
         }
      }
   }

/*
* Single Operand Right Shift
*/
void bigint_shr1(word x[], size_t x_size, size_t word_shift, size_t bit_shift)
   {
   if(x_size < word_shift)
      {
      clear_mem(x, x_size);
      return;
      }

   if(word_shift)
      {
      copy_mem(x, x + word_shift, x_size - word_shift);
      clear_mem(x + x_size - word_shift, word_shift);
      }

   if(bit_shift)
      {
      word carry = 0;

      size_t top = x_size - word_shift;

      while(top >= 4)
         {
         word w = x[top-1];
         x[top-1] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));

         w = x[top-2];
         x[top-2] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));

         w = x[top-3];
         x[top-3] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));

         w = x[top-4];
         x[top-4] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));

         top -= 4;
         }

      while(top)
         {
         word w = x[top-1];
         x[top-1] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));

         top--;
         }
      }
   }

/*
* Two Operand Left Shift
*/
void bigint_shl2(word y[], const word x[], size_t x_size,
                 size_t word_shift, size_t bit_shift)
   {
   for(size_t j = 0; j != x_size; ++j)
      y[j + word_shift] = x[j];
   if(bit_shift)
      {
      word carry = 0;
      for(size_t j = word_shift; j != x_size + word_shift + 1; ++j)
         {
         word w = y[j];
         y[j] = (w << bit_shift) | carry;
         carry = (w >> (MP_WORD_BITS - bit_shift));
         }
      }
   }

/*
* Two Operand Right Shift
*/
void bigint_shr2(word y[], const word x[], size_t x_size,
                 size_t word_shift, size_t bit_shift)
   {
   if(x_size < word_shift) return;

   for(size_t j = 0; j != x_size - word_shift; ++j)
      y[j] = x[j + word_shift];
   if(bit_shift)
      {
      word carry = 0;
      for(size_t j = x_size - word_shift; j > 0; --j)
         {
         word w = y[j-1];
         y[j-1] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));
         }
      }
   }

/*
* Compare two MP integers
*/
int32_t bigint_cmp(const word x[], size_t x_size,
                  const word y[], size_t y_size)
   {
   if(x_size < y_size) { return (-bigint_cmp(y, y_size, x, x_size)); }

   while(x_size > y_size)
      {
      if(x[x_size-1])
         return 1;
      x_size--;
      }

   for(size_t i = x_size; i > 0; --i)
      {
      if(x[i-1] > y[i-1])
         return 1;
      if(x[i-1] < y[i-1])
         return -1;
      }

   return 0;
   }

/*
* Do a 2-word/1-word Division
*/
word bigint_divop(word n1, word n0, word d)
   {
   if(d == 0)
      throw Invalid_Argument("bigint_divop divide by zero");

#if defined(BOTAN_HAS_MP_DWORD)
   return ((static_cast<dword>(n1) << MP_WORD_BITS) | n0) / d;
#else

   word high = n1 % d, quotient = 0;

   for(size_t i = 0; i != MP_WORD_BITS; ++i)
      {
      word high_top_bit = (high & MP_WORD_TOP_BIT);

      high <<= 1;
      high |= (n0 >> (MP_WORD_BITS-1-i)) & 1;
      quotient <<= 1;

      if(high_top_bit || high >= d)
         {
         high -= d;
         quotient |= 1;
         }
      }

   return quotient;
#endif
   }

/*
* Do a 2-word/1-word Modulo
*/
word bigint_modop(word n1, word n0, word d)
   {
   word z = bigint_divop(n1, n0, d);
   word dummy = 0;
   z = word_madd2(z, d, &dummy);
   return (n0-z);
   }

}
/*
* Multiplication and Squaring
* (C) 1999-2010 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

const size_t KARATSUBA_MULTIPLY_THRESHOLD = 32;
const size_t KARATSUBA_SQUARE_THRESHOLD = 32;

/*
* Simple O(N^2) Multiplication
*/
void basecase_mul(word z[],
                  const word x[], size_t x_size,
                  const word y[], size_t y_size)
   {
   const size_t x_size_8 = x_size - (x_size % 8);

   clear_mem(z, x_size + y_size);

   for(size_t i = 0; i != y_size; ++i)
      {
      const word y_i = y[i];

      word carry = 0;

      for(size_t j = 0; j != x_size_8; j += 8)
         carry = word8_madd3(z + i + j, x + j, y_i, carry);

      for(size_t j = x_size_8; j != x_size; ++j)
         z[i+j] = word_madd3(x[j], y_i, z[i+j], &carry);

      z[x_size+i] = carry;
      }
   }

/*
* Karatsuba Multiplication Operation
*/
void karatsuba_mul(word z[], const word x[], const word y[], size_t N,
                   word workspace[])
   {
   if(N < KARATSUBA_MULTIPLY_THRESHOLD || N % 2)
      {
      if(N == 6)
         return bigint_comba_mul6(z, x, y);
      else if(N == 8)
         return bigint_comba_mul8(z, x, y);
      else if(N == 16)
         return bigint_comba_mul16(z, x, y);
      else
         return basecase_mul(z, x, N, y, N);
      }

   const size_t N2 = N / 2;

   const word* x0 = x;
   const word* x1 = x + N2;
   const word* y0 = y;
   const word* y1 = y + N2;
   word* z0 = z;
   word* z1 = z + N;

   const int32_t cmp0 = bigint_cmp(x0, N2, x1, N2);
   const int32_t cmp1 = bigint_cmp(y1, N2, y0, N2);

   clear_mem(workspace, 2*N);

   /*
   * If either of cmp0 or cmp1 is zero then z0 or z1 resp is zero here,
   * resulting in a no-op - z0*z1 will be equal to zero so we don't need to do
   * anything, clear_mem above already set the correct result.
   *
   * However we ignore the result of the comparisons and always perform the
   * subtractions and recursively multiply to avoid the timing channel.
   */

   //if(cmp0 && cmp1)
      {
      if(cmp0 > 0)
         bigint_sub3(z0, x0, N2, x1, N2);
      else
         bigint_sub3(z0, x1, N2, x0, N2);

      if(cmp1 > 0)
         bigint_sub3(z1, y1, N2, y0, N2);
      else
         bigint_sub3(z1, y0, N2, y1, N2);

      karatsuba_mul(workspace, z0, z1, N2, workspace+N);
      }

   karatsuba_mul(z0, x0, y0, N2, workspace+N);
   karatsuba_mul(z1, x1, y1, N2, workspace+N);

   const word ws_carry = bigint_add3_nc(workspace + N, z0, N, z1, N);
   word z_carry = bigint_add2_nc(z + N2, N, workspace + N, N);

   z_carry += bigint_add2_nc(z + N + N2, N2, &ws_carry, 1);
   bigint_add2_nc(z + N + N2, N2, &z_carry, 1);

   if((cmp0 == cmp1) || (cmp0 == 0) || (cmp1 == 0))
      bigint_add2(z + N2, 2*N-N2, workspace, N);
   else
      bigint_sub2(z + N2, 2*N-N2, workspace, N);
   }

/*
* Karatsuba Squaring Operation
*/
void karatsuba_sqr(word z[], const word x[], size_t N, word workspace[])
   {
   if(N < KARATSUBA_SQUARE_THRESHOLD || N % 2)
      {
      if(N == 6)
         return bigint_comba_sqr6(z, x);
      else if(N == 8)
         return bigint_comba_sqr8(z, x);
      else if(N == 16)
         return bigint_comba_sqr16(z, x);
      else
         return basecase_mul(z, x, N, x, N);
      }

   const size_t N2 = N / 2;

   const word* x0 = x;
   const word* x1 = x + N2;
   word* z0 = z;
   word* z1 = z + N;

   const int32_t cmp = bigint_cmp(x0, N2, x1, N2);

   clear_mem(workspace, 2*N);

   // See comment in karatsuba_mul

   //if(cmp)
      {
      if(cmp > 0)
         bigint_sub3(z0, x0, N2, x1, N2);
      else
         bigint_sub3(z0, x1, N2, x0, N2);

      karatsuba_sqr(workspace, z0, N2, workspace+N);
      }

   karatsuba_sqr(z0, x0, N2, workspace+N);
   karatsuba_sqr(z1, x1, N2, workspace+N);

   const word ws_carry = bigint_add3_nc(workspace + N, z0, N, z1, N);
   word z_carry = bigint_add2_nc(z + N2, N, workspace + N, N);

   z_carry += bigint_add2_nc(z + N + N2, N2, &ws_carry, 1);
   bigint_add2_nc(z + N + N2, N2, &z_carry, 1);

   /*
   * This is only actually required if cmp is != 0, however
   * if cmp==0 then workspace[0:N] == 0 and avoiding the jump
   * hides a timing channel.
   */
   bigint_sub2(z + N2, 2*N-N2, workspace, N);
   }

/*
* Pick a good size for the Karatsuba multiply
*/
size_t karatsuba_size(size_t z_size,
                      size_t x_size, size_t x_sw,
                      size_t y_size, size_t y_sw)
   {
   if(x_sw > x_size || x_sw > y_size || y_sw > x_size || y_sw > y_size)
      return 0;

   if(((x_size == x_sw) && (x_size % 2)) ||
      ((y_size == y_sw) && (y_size % 2)))
      return 0;

   const size_t start = (x_sw > y_sw) ? x_sw : y_sw;
   const size_t end = (x_size < y_size) ? x_size : y_size;

   if(start == end)
      {
      if(start % 2)
         return 0;
      return start;
      }

   for(size_t j = start; j <= end; ++j)
      {
      if(j % 2)
         continue;

      if(2*j > z_size)
         return 0;

      if(x_sw <= j && j <= x_size && y_sw <= j && j <= y_size)
         {
         if(j % 4 == 2 &&
            (j+2) <= x_size && (j+2) <= y_size && 2*(j+2) <= z_size)
            return j+2;
         return j;
         }
      }

   return 0;
   }

/*
* Pick a good size for the Karatsuba squaring
*/
size_t karatsuba_size(size_t z_size, size_t x_size, size_t x_sw)
   {
   if(x_sw == x_size)
      {
      if(x_sw % 2)
         return 0;
      return x_sw;
      }

   for(size_t j = x_sw; j <= x_size; ++j)
      {
      if(j % 2)
         continue;

      if(2*j > z_size)
         return 0;

      if(j % 4 == 2 && (j+2) <= x_size && 2*(j+2) <= z_size)
         return j+2;
      return j;
      }

   return 0;
   }

}

/*
* Multiplication Algorithm Dispatcher
*/
void bigint_mul(BigInt& z, const BigInt& x, const BigInt& y, word workspace[])
   {
   return bigint_mul(z.mutable_data(), z.size(),
                     x.data(), x.size(), x.sig_words(),
                     y.data(), y.size(), y.sig_words(),
                     workspace);
   }

void bigint_mul(word z[], size_t z_size,
                const word x[], size_t x_size, size_t x_sw,
                const word y[], size_t y_size, size_t y_sw,
                word workspace[])
   {
   clear_mem(z, z_size);

   if(x_sw == 1)
      {
      bigint_linmul3(z, y, y_sw, x[0]);
      }
   else if(y_sw == 1)
      {
      bigint_linmul3(z, x, x_sw, y[0]);
      }
   else if(x_sw <= 4 && x_size >= 4 &&
           y_sw <= 4 && y_size >= 4 && z_size >= 8)
      {
      bigint_comba_mul4(z, x, y);
      }
   else if(x_sw <= 6 && x_size >= 6 &&
           y_sw <= 6 && y_size >= 6 && z_size >= 12)
      {
      bigint_comba_mul6(z, x, y);
      }
   else if(x_sw <= 8 && x_size >= 8 &&
           y_sw <= 8 && y_size >= 8 && z_size >= 16)
      {
      bigint_comba_mul8(z, x, y);
      }
   else if(x_sw <= 9 && x_size >= 9 &&
           y_sw <= 9 && y_size >= 9 && z_size >= 18)
      {
      bigint_comba_mul9(z, x, y);
      }
   else if(x_sw <= 16 && x_size >= 16 &&
           y_sw <= 16 && y_size >= 16 && z_size >= 32)
      {
      bigint_comba_mul16(z, x, y);
      }
   else if(x_sw < KARATSUBA_MULTIPLY_THRESHOLD ||
           y_sw < KARATSUBA_MULTIPLY_THRESHOLD ||
           !workspace)
      {
      basecase_mul(z, x, x_sw, y, y_sw);
      }
   else
      {
      const size_t N = karatsuba_size(z_size, x_size, x_sw, y_size, y_sw);

      if(N)
         karatsuba_mul(z, x, y, N, workspace);
      else
         basecase_mul(z, x, x_sw, y, y_sw);
      }
   }

/*
* Squaring Algorithm Dispatcher
*/
void bigint_sqr(word z[], size_t z_size, word workspace[],
                const word x[], size_t x_size, size_t x_sw)
   {
   BOTAN_ASSERT(z_size/2 >= x_sw, "Output size is sufficient");

   if(x_sw == 1)
      {
      bigint_linmul3(z, x, x_sw, x[0]);
      }
   else if(x_sw <= 4 && x_size >= 4 && z_size >= 8)
      {
      bigint_comba_sqr4(z, x);
      }
   else if(x_sw <= 6 && x_size >= 6 && z_size >= 12)
      {
      bigint_comba_sqr6(z, x);
      }
   else if(x_sw <= 8 && x_size >= 8 && z_size >= 16)
      {
      bigint_comba_sqr8(z, x);
      }
   else if(x_sw == 9 && x_size >= 9 && z_size >= 18)
      {
      bigint_comba_sqr9(z, x);
      }
   else if(x_sw <= 16 && x_size >= 16 && z_size >= 32)
      {
      bigint_comba_sqr16(z, x);
      }
   else if(x_size < KARATSUBA_SQUARE_THRESHOLD || !workspace)
      {
      basecase_mul(z, x, x_sw, x, x_sw);
      }
   else
      {
      const size_t N = karatsuba_size(z_size, x_size, x_sw);

      if(N)
         karatsuba_sqr(z, x, N, workspace);
      else
         basecase_mul(z, x, x_sw, x, x_sw);
      }
   }

}
/*
* Montgomery Reduction
* (C) 1999-2011 Jack Lloyd
*     2006 Luca Piccarreta
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Montgomery Reduction Algorithm
*/
void bigint_monty_redc(word z[],
                       const word p[], size_t p_size,
                       word p_dash, word ws[])
   {
   const size_t z_size = 2*(p_size+1);

   CT::poison(z, z_size);
   CT::poison(p, p_size);
   CT::poison(ws, 2*(p_size+1));

   const size_t blocks_of_8 = p_size - (p_size % 8);

   for(size_t i = 0; i != p_size; ++i)
      {
      word* z_i = z + i;

      const word y = z_i[0] * p_dash;

      /*
      bigint_linmul3(ws, p, p_size, y);
      bigint_add2(z_i, z_size - i, ws, p_size+1);
      */

      word carry = 0;

      for(size_t j = 0; j != blocks_of_8; j += 8)
         carry = word8_madd3(z_i + j, p + j, y, carry);

      for(size_t j = blocks_of_8; j != p_size; ++j)
         z_i[j] = word_madd3(p[j], y, z_i[j], &carry);

      word z_sum = z_i[p_size] + carry;
      carry = (z_sum < z_i[p_size]);
      z_i[p_size] = z_sum;

      for(size_t j = p_size + 1; j < z_size - i; ++j)
         {
         z_i[j] += carry;
         carry = carry & !z_i[j];
         }
      }

   /*
   * The result might need to be reduced mod p. To avoid a timing
   * channel, always perform the subtraction. If in the compution
   * of x - p a borrow is required then x was already < p.
   *
   * x - p starts at ws[0] and is p_size+1 bytes long
   * x starts at ws[p_size+1] and is also p_size+1 bytes log
   * (that's the copy_mem)
   *
   * Select which address to copy from indexing off of the final
   * borrow.
   */

   word borrow = 0;
   for(size_t i = 0; i != p_size; ++i)
      ws[i] = word_sub(z[p_size + i], p[i], &borrow);

   ws[p_size] = word_sub(z[p_size+p_size], 0, &borrow);

   copy_mem(ws + p_size + 1, z + p_size, p_size + 1);

   CT::conditional_copy_mem(borrow, z, ws + (p_size + 1), ws, (p_size + 1));
   clear_mem(z + p_size + 1, z_size - p_size - 1);

   CT::unpoison(z, z_size);
   CT::unpoison(p, p_size);
   CT::unpoison(ws, 2*(p_size+1));

   // This check comes after we've used it but that's ok here
   CT::unpoison(&borrow, 1);
   BOTAN_ASSERT(borrow == 0 || borrow == 1, "Expected borrow");
   }

void bigint_monty_mul(BigInt& z, const BigInt& x, const BigInt& y,
                      const word p[], size_t p_size, word p_dash,
                      word ws[])
   {
   bigint_mul(z, x, y, &ws[0]);

   bigint_monty_redc(z.mutable_data(),
                     p, p_size, p_dash,
                     ws);
   }

void bigint_monty_sqr(BigInt& z, const BigInt& x, const word p[],
                      size_t p_size, word p_dash, word ws[])
   {
   bigint_sqr(z.mutable_data(), z.size(), &ws[0],
              x.data(), x.size(), x.sig_words());

   bigint_monty_redc(z.mutable_data(),
                     p, p_size, p_dash,
                     ws);
   }

}
/*
* DSA Parameter Generation
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

/*
* Check if this size is allowed by FIPS 186-3
*/
bool fips186_3_valid_size(size_t pbits, size_t qbits)
   {
   if(qbits == 160)
      return (pbits == 1024);

   if(qbits == 224)
      return (pbits == 2048);

   if(qbits == 256)
      return (pbits == 2048 || pbits == 3072);

   return false;
   }

}

/*
* Attempt DSA prime generation with given seed
*/
bool generate_dsa_primes(RandomNumberGenerator& rng,
                         BigInt& p, BigInt& q,
                         size_t pbits, size_t qbits,
                         const std::vector<uint8_t>& seed_c,
                         size_t offset)
   {
   if(!fips186_3_valid_size(pbits, qbits))
      throw Invalid_Argument(
         "FIPS 186-3 does not allow DSA domain parameters of " +
         std::to_string(pbits) + "/" + std::to_string(qbits) + " bits long");

   if(seed_c.size() * 8 < qbits)
      throw Invalid_Argument(
         "Generating a DSA parameter set with a " + std::to_string(qbits) +
         "long q requires a seed at least as many bits long");

   const std::string hash_name = "SHA-" + std::to_string(qbits);
   std::unique_ptr<HashFunction> hash(HashFunction::create_or_throw(hash_name));

   const size_t HASH_SIZE = hash->output_length();

   class Seed final
      {
      public:
         explicit Seed(const std::vector<uint8_t>& s) : m_seed(s) {}

         const std::vector<uint8_t>& value() const { return m_seed; }

         Seed& operator++()
            {
            for(size_t j = m_seed.size(); j > 0; --j)
               if(++m_seed[j-1])
                  break;
            return (*this);
            }
      private:
         std::vector<uint8_t> m_seed;
      };

   Seed seed(seed_c);

   q.binary_decode(hash->process(seed.value()));
   q.set_bit(qbits-1);
   q.set_bit(0);

   if(!is_prime(q, rng, 126))
      return false;

   const size_t n = (pbits-1) / (HASH_SIZE * 8),
                b = (pbits-1) % (HASH_SIZE * 8);

   BigInt X;
   std::vector<uint8_t> V(HASH_SIZE * (n+1));

   for(size_t j = 0; j != 4*pbits; ++j)
      {
      for(size_t k = 0; k <= n; ++k)
         {
         ++seed;
         hash->update(seed.value());
         hash->final(&V[HASH_SIZE * (n-k)]);
         }

      if(j >= offset)
         {
         X.binary_decode(&V[HASH_SIZE - 1 - b/8],
                         V.size() - (HASH_SIZE - 1 - b/8));
         X.set_bit(pbits-1);

         p = X - (X % (2*q) - 1);

         if(p.bits() == pbits && is_prime(p, rng, 126))
            return true;
         }
      }
   return false;
   }

/*
* Generate DSA Primes
*/
std::vector<uint8_t> generate_dsa_primes(RandomNumberGenerator& rng,
                                      BigInt& p, BigInt& q,
                                      size_t pbits, size_t qbits)
   {
   while(true)
      {
      std::vector<uint8_t> seed(qbits / 8);
      rng.randomize(seed.data(), seed.size());

      if(generate_dsa_primes(rng, p, q, pbits, qbits, seed))
         return seed;
      }
   }

}
/*
* Jacobi Function
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Calculate the Jacobi symbol
*/
int32_t jacobi(const BigInt& a, const BigInt& n)
   {
   if(a.is_negative())
      throw Invalid_Argument("jacobi: first argument must be non-negative");
   if(n.is_even() || n < 2)
      throw Invalid_Argument("jacobi: second argument must be odd and > 1");

   BigInt x = a, y = n;
   int32_t J = 1;

   while(y > 1)
      {
      x %= y;
      if(x > y / 2)
         {
         x = y - x;
         if(y % 4 == 3)
            J = -J;
         }
      if(x.is_zero())
         return 0;

      size_t shifts = low_zero_bits(x);
      x >>= shifts;
      if(shifts % 2)
         {
         word y_mod_8 = y % 8;
         if(y_mod_8 == 3 || y_mod_8 == 5)
            J = -J;
         }

      if(x % 4 == 3 && y % 4 == 3)
         J = -J;
      std::swap(x, y);
      }
   return J;
   }

}
/*
* Prime Generation
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Generate a random prime
*/
BigInt random_prime(RandomNumberGenerator& rng,
                    size_t bits, const BigInt& coprime,
                    size_t equiv, size_t modulo)
   {
   if(coprime <= 0)
      {
      throw Invalid_Argument("random_prime: coprime must be > 0");
      }
   if(modulo % 2 == 1 || modulo == 0)
      {
      throw Invalid_Argument("random_prime: Invalid modulo value");
      }
   if(equiv >= modulo || equiv % 2 == 0)
      {
      throw Invalid_Argument("random_prime: equiv must be < modulo, and odd");
      }

   // Handle small values:
   if(bits <= 1)
      {
      throw Invalid_Argument("random_prime: Can't make a prime of " +
                             std::to_string(bits) + " bits");
      }
   else if(bits == 2)
      {
      return ((rng.next_byte() % 2) ? 2 : 3);
      }
   else if(bits == 3)
      {
      return ((rng.next_byte() % 2) ? 5 : 7);
      }
   else if(bits == 4)
      {
      return ((rng.next_byte() % 2) ? 11 : 13);
      }

   while(true)
      {
      BigInt p(rng, bits);

      // Force lowest and two top bits on
      p.set_bit(bits - 1);
      p.set_bit(bits - 2);
      p.set_bit(0);

      if(p % modulo != equiv)
         p += (modulo - p % modulo) + equiv;

      const size_t sieve_size = std::min(bits / 2, PRIME_TABLE_SIZE);
      secure_vector<uint16_t> sieve(sieve_size);

      for(size_t j = 0; j != sieve.size(); ++j)
         sieve[j] = static_cast<uint16_t>(p % PRIMES[j]);

      size_t counter = 0;
      while(true)
         {
         ++counter;

         if(counter >= 4096)
            {
            break; // don't try forever, choose a new starting point
            }

         p += modulo;

         if(p.bits() > bits)
            break;

         bool passes_sieve = true;
         for(size_t j = 0; j != sieve.size(); ++j)
            {
            sieve[j] = (sieve[j] + modulo) % PRIMES[j];
            if(sieve[j] == 0)
               {
               passes_sieve = false;
               break;
               }
            }

         if(!passes_sieve)
            continue;

         if(gcd(p - 1, coprime) != 1)
            continue;

         if(is_prime(p, rng, 128, true))
            {
            return p;
            }
         }
      }
   }

/*
* Generate a random safe prime
*/
BigInt random_safe_prime(RandomNumberGenerator& rng, size_t bits)
   {
   if(bits <= 64)
      throw Invalid_Argument("random_safe_prime: Can't make a prime of " +
                             std::to_string(bits) + " bits");

   BigInt p;
   do
      p = (random_prime(rng, bits - 1) << 1) + 1;
   while(!is_prime(p, rng, 128, true));

   return p;
   }

}
/*
* Fused and Important MP Algorithms
* (C) 1999-2007 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Square a BigInt
*/
BigInt square(const BigInt& x)
   {
   const size_t x_sw = x.sig_words();

   BigInt z(BigInt::Positive, round_up(2*x_sw, 16));
   secure_vector<word> workspace(z.size());

   bigint_sqr(z.mutable_data(), z.size(),
              workspace.data(),
              x.data(), x.size(), x_sw);
   return z;
   }

/*
* Multiply-Add Operation
*/
BigInt mul_add(const BigInt& a, const BigInt& b, const BigInt& c)
   {
   if(c.is_negative())
      throw Invalid_Argument("mul_add: Third argument must be > 0");

   BigInt::Sign sign = BigInt::Positive;
   if(a.sign() != b.sign())
      sign = BigInt::Negative;

   BigInt r(sign, std::max(a.size() + b.size(), c.sig_words()) + 1);
   secure_vector<word> workspace(r.size());

   bigint_mul(r, a, b, workspace.data());

   const size_t r_size = std::max(r.sig_words(), c.sig_words());
   bigint_add2(r.mutable_data(), r_size, c.data(), c.sig_words());
   return r;
   }

/*
* Subtract-Multiply Operation
*/
BigInt sub_mul(const BigInt& a, const BigInt& b, const BigInt& c)
   {
   if(a.is_negative() || b.is_negative())
      throw Invalid_Argument("sub_mul: First two arguments must be >= 0");

   BigInt r = a;
   r -= b;
   r *= c;
   return r;
   }

/*
* Multiply-Subtract Operation
*/
BigInt mul_sub(const BigInt& a, const BigInt& b, const BigInt& c)
   {
   if(c.is_negative() || c.is_zero())
      throw Invalid_Argument("mul_sub: Third argument must be > 0");

   BigInt r = a;
   r *= b;
   r -= c;
   return r;
   }

}
/*
* Number Theory Functions
* (C) 1999-2011,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Return the number of 0 bits at the end of n
*/
size_t low_zero_bits(const BigInt& n)
   {
   size_t low_zero = 0;

   if(n.is_positive() && n.is_nonzero())
      {
      for(size_t i = 0; i != n.size(); ++i)
         {
         const word x = n.word_at(i);

         if(x)
            {
            low_zero += ctz(x);
            break;
            }
         else
            low_zero += BOTAN_MP_WORD_BITS;
         }
      }

   return low_zero;
   }

/*
* Calculate the GCD
*/
BigInt gcd(const BigInt& a, const BigInt& b)
   {
   if(a.is_zero() || b.is_zero()) return 0;
   if(a == 1 || b == 1)           return 1;

   BigInt x = a, y = b;
   x.set_sign(BigInt::Positive);
   y.set_sign(BigInt::Positive);
   size_t shift = std::min(low_zero_bits(x), low_zero_bits(y));

   x >>= shift;
   y >>= shift;

   while(x.is_nonzero())
      {
      x >>= low_zero_bits(x);
      y >>= low_zero_bits(y);
      if(x >= y) { x -= y; x >>= 1; }
      else       { y -= x; y >>= 1; }
      }

   return (y << shift);
   }

/*
* Calculate the LCM
*/
BigInt lcm(const BigInt& a, const BigInt& b)
   {
   return ((a * b) / gcd(a, b));
   }

/*
Sets result to a^-1 * 2^k mod a
with n <= k <= 2n
Returns k

"The Montgomery Modular Inverse - Revisited" Çetin Koç, E. Savas
https://citeseerx.ist.psu.edu/viewdoc/citations?doi=10.1.1.75.8377

A const time implementation of this algorithm is described in
"Constant Time Modular Inversion" Joppe W. Bos
http://www.joppebos.com/files/CTInversion.pdf
*/
size_t almost_montgomery_inverse(BigInt& result,
                                 const BigInt& a,
                                 const BigInt& p)
   {
   size_t k = 0;

   BigInt u = p, v = a, r = 0, s = 1;

   while(v > 0)
      {
      if(u.is_even())
         {
         u >>= 1;
         s <<= 1;
         }
      else if(v.is_even())
         {
         v >>= 1;
         r <<= 1;
         }
      else if(u > v)
         {
         u -= v;
         u >>= 1;
         r += s;
         s <<= 1;
         }
      else
         {
         v -= u;
         v >>= 1;
         s += r;
         r <<= 1;
         }

      ++k;
      }

   if(r >= p)
      {
      r = r - p;
      }

   result = p - r;

   return k;
   }

BigInt normalized_montgomery_inverse(const BigInt& a, const BigInt& p)
   {
   BigInt r;
   size_t k = almost_montgomery_inverse(r, a, p);

   for(size_t i = 0; i != k; ++i)
      {
      if(r.is_odd())
         r += p;
      r >>= 1;
      }

   return r;
   }

BigInt ct_inverse_mod_odd_modulus(const BigInt& n, const BigInt& mod)
   {
   if(n.is_negative() || mod.is_negative())
      throw Invalid_Argument("ct_inverse_mod_odd_modulus: arguments must be non-negative");
   if(mod < 3 || mod.is_even())
      throw Invalid_Argument("Bad modulus to ct_inverse_mod_odd_modulus");

   /*
   This uses a modular inversion algorithm designed by Niels Möller
   and implemented in Nettle. The same algorithm was later also
   adapted to GMP in mpn_sec_invert.

   It can be easily implemented in a way that does not depend on
   secret branches or memory lookups, providing resistance against
   some forms of side channel attack.

   There is also a description of the algorithm in Appendix 5 of "Fast
   Software Polynomial Multiplication on ARM Processors using the NEON Engine"
   by Danilo Câmara, Conrado P. L. Gouvêa, Julio López, and Ricardo
   Dahab in LNCS 8182
      https://conradoplg.cryptoland.net/files/2010/12/mocrysen13.pdf

   Thanks to Niels for creating the algorithm, explaining some things
   about it, and the reference to the paper.
   */

   // todo allow this to be pre-calculated and passed in as arg
   BigInt mp1o2 = (mod + 1) >> 1;

   const size_t mod_words = mod.sig_words();
   BOTAN_ASSERT(mod_words > 0, "Not empty");

   BigInt a = n;
   BigInt b = mod;
   BigInt u = 1, v = 0;

   a.grow_to(mod_words);
   u.grow_to(mod_words);
   v.grow_to(mod_words);
   mp1o2.grow_to(mod_words);

   secure_vector<word>& a_w = a.get_word_vector();
   secure_vector<word>& b_w = b.get_word_vector();
   secure_vector<word>& u_w = u.get_word_vector();
   secure_vector<word>& v_w = v.get_word_vector();

   CT::poison(a_w.data(), a_w.size());
   CT::poison(b_w.data(), b_w.size());
   CT::poison(u_w.data(), u_w.size());
   CT::poison(v_w.data(), v_w.size());

   // Only n.bits() + mod.bits() iterations are required, but avoid leaking the size of n
   size_t bits = 2 * mod.bits();

   while(bits--)
      {
      /*
      const word odd = a.is_odd();
      a -= odd * b;
      const word underflow = a.is_negative();
      b += a * underflow;
      a.set_sign(BigInt::Positive);

      a >>= 1;

      if(underflow)
         {
         std::swap(u, v);
         }

      u -= odd * v;
      u += u.is_negative() * mod;

      const word odd_u = u.is_odd();

      u >>= 1;
      u += mp1o2 * odd_u;
      */

      const word odd_a = a_w[0] & 1;

      //if(odd_a) a -= b
      word underflow = bigint_cnd_sub(odd_a, a_w.data(), b_w.data(), mod_words);

      //if(underflow) { b -= a; a = abs(a); swap(u, v); }
      bigint_cnd_add(underflow, b_w.data(), a_w.data(), mod_words);
      bigint_cnd_abs(underflow, a_w.data(), mod_words);
      bigint_cnd_swap(underflow, u_w.data(), v_w.data(), mod_words);

      // a >>= 1
      bigint_shr1(a_w.data(), mod_words, 0, 1);

      //if(odd_a) u -= v;
      word borrow = bigint_cnd_sub(odd_a, u_w.data(), v_w.data(), mod_words);

      // if(borrow) u += p
      bigint_cnd_add(borrow, u_w.data(), mod.data(), mod_words);

      const word odd_u = u_w[0] & 1;

      // u >>= 1
      bigint_shr1(u_w.data(), mod_words, 0, 1);

      //if(odd_u) u += mp1o2;
      bigint_cnd_add(odd_u, u_w.data(), mp1o2.data(), mod_words);
      }

   CT::unpoison(a_w.data(), a_w.size());
   CT::unpoison(b_w.data(), b_w.size());
   CT::unpoison(u_w.data(), u_w.size());
   CT::unpoison(v_w.data(), v_w.size());

   BOTAN_ASSERT(a.is_zero(), "A is zero");

   if(b != 1)
      return 0;

   return v;
   }

/*
* Find the Modular Inverse
*/
BigInt inverse_mod(const BigInt& n, const BigInt& mod)
   {
   if(mod.is_zero())
      throw BigInt::DivideByZero();
   if(mod.is_negative() || n.is_negative())
      throw Invalid_Argument("inverse_mod: arguments must be non-negative");

   if(n.is_zero() || (n.is_even() && mod.is_even()))
      return 0; // fast fail checks

   if(mod.is_odd())
      return ct_inverse_mod_odd_modulus(n, mod);

   BigInt u = mod, v = n;
   BigInt A = 1, B = 0, C = 0, D = 1;

   while(u.is_nonzero())
      {
      const size_t u_zero_bits = low_zero_bits(u);
      u >>= u_zero_bits;
      for(size_t i = 0; i != u_zero_bits; ++i)
         {
         if(A.is_odd() || B.is_odd())
            { A += n; B -= mod; }
         A >>= 1; B >>= 1;
         }

      const size_t v_zero_bits = low_zero_bits(v);
      v >>= v_zero_bits;
      for(size_t i = 0; i != v_zero_bits; ++i)
         {
         if(C.is_odd() || D.is_odd())
            { C += n; D -= mod; }
         C >>= 1; D >>= 1;
         }

      if(u >= v) { u -= v; A -= C; B -= D; }
      else       { v -= u; C -= A; D -= B; }
      }

   if(v != 1)
      return 0; // no modular inverse

   while(D.is_negative()) D += mod;
   while(D >= mod) D -= mod;

   return D;
   }

word monty_inverse(word input)
   {
   if(input == 0)
      throw Exception("monty_inverse: divide by zero");

   word b = input;
   word x2 = 1, x1 = 0, y2 = 0, y1 = 1;

   // First iteration, a = n+1
   word q = bigint_divop(1, 0, b);
   word r = (MP_WORD_MAX - q*b) + 1;
   word x = x2 - q*x1;
   word y = y2 - q*y1;

   word a = b;
   b = r;
   x2 = x1;
   x1 = x;
   y2 = y1;
   y1 = y;

   while(b > 0)
      {
      q = a / b;
      r = a - q*b;
      x = x2 - q*x1;
      y = y2 - q*y1;

      a = b;
      b = r;
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;
      }

   const word check = y2 * input;
   BOTAN_ASSERT_EQUAL(check, 1, "monty_inverse result is inverse of input");

   // Now invert in addition space
   y2 = (MP_WORD_MAX - y2) + 1;

   return y2;
   }

/*
* Modular Exponentiation
*/
BigInt power_mod(const BigInt& base, const BigInt& exp, const BigInt& mod)
   {
   Power_Mod pow_mod(mod);

   /*
   * Calling set_base before set_exponent means we end up using a
   * minimal window. This makes sense given that here we know that any
   * precomputation is wasted.
   */

   if(base.is_negative())
      {
      pow_mod.set_base(-base);
      pow_mod.set_exponent(exp);
      if(exp.is_even())
         return pow_mod.execute();
      else
         return (mod - pow_mod.execute());
      }
   else
      {
      pow_mod.set_base(base);
      pow_mod.set_exponent(exp);
      return pow_mod.execute();
      }
   }

namespace {

bool mr_witness(BigInt&& y,
                const Modular_Reducer& reducer_n,
                const BigInt& n_minus_1, size_t s)
   {
   if(y == 1 || y == n_minus_1)
      return false;

   for(size_t i = 1; i != s; ++i)
      {
      y = reducer_n.square(y);

      if(y == 1) // found a non-trivial square root
         return true;

      if(y == n_minus_1) // -1, trivial square root, so give up
         return false;
      }

   return true; // fails Fermat test
   }

size_t mr_test_iterations(size_t n_bits, size_t prob, bool random)
   {
   const size_t base = (prob + 2) / 2; // worst case 4^-t error rate

   /*
   * For randomly chosen numbers we can use the estimates from
   * http://www.math.dartmouth.edu/~carlp/PDF/paper88.pdf
   *
   * These values are derived from the inequality for p(k,t) given on
   * the second page.
   */
   if(random && prob <= 80)
      {
      if(n_bits >= 1536)
         return 2; // < 2^-89
      if(n_bits >= 1024)
         return 4; // < 2^-89
      if(n_bits >= 512)
         return 5; // < 2^-80
      if(n_bits >= 256)
         return 11; // < 2^-80
      }

   return base;
   }

}

/*
* Test for primaility using Miller-Rabin
*/
bool is_prime(const BigInt& n, RandomNumberGenerator& rng,
              size_t prob, bool is_random)
   {
   if(n == 2)
      return true;
   if(n <= 1 || n.is_even())
      return false;

   // Fast path testing for small numbers (<= 65521)
   if(n <= PRIMES[PRIME_TABLE_SIZE-1])
      {
      const uint16_t num = static_cast<uint16_t>(n.word_at(0));

      return std::binary_search(PRIMES, PRIMES + PRIME_TABLE_SIZE, num);
      }

   const size_t test_iterations = mr_test_iterations(n.bits(), prob, is_random);

   const BigInt n_minus_1 = n - 1;
   const size_t s = low_zero_bits(n_minus_1);

   Fixed_Exponent_Power_Mod pow_mod(n_minus_1 >> s, n);
   Modular_Reducer reducer(n);

   for(size_t i = 0; i != test_iterations; ++i)
      {
      const BigInt a = BigInt::random_integer(rng, 2, n_minus_1);
      BigInt y = pow_mod(a);

      if(mr_witness(std::move(y), reducer, n_minus_1, s))
         return false;
      }

   return true;
   }

}
/*
* Modular Exponentiation Proxy
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Power_Mod Constructor
*/
Power_Mod::Power_Mod(const BigInt& n, Usage_Hints hints, bool disable_monty)
   {
   set_modulus(n, hints, disable_monty);
   }

/*
* Power_Mod Copy Constructor
*/
Power_Mod::Power_Mod(const Power_Mod& other)
   {
   if(other.m_core.get())
      m_core.reset(other.m_core->copy());
   }

/*
* Power_Mod Assignment Operator
*/
Power_Mod& Power_Mod::operator=(const Power_Mod& other)
   {
   if(this != &other)
      {
      if(other.m_core)
         m_core.reset(other.m_core->copy());
      else
         m_core.reset();
      }
   return (*this);
   }

/*
* Set the modulus
*/
void Power_Mod::set_modulus(const BigInt& n, Usage_Hints hints, bool disable_monty) const
   {
   // Allow set_modulus(0) to mean "drop old state"

   m_core.reset();

   if(n != 0)
      {
      if(n.is_odd() && disable_monty == false)
         m_core.reset(new Montgomery_Exponentiator(n, hints));
      else
         m_core.reset(new Fixed_Window_Exponentiator(n, hints));
      }
   }

/*
* Set the base
*/
void Power_Mod::set_base(const BigInt& b) const
   {
   if(b.is_zero() || b.is_negative())
      throw Invalid_Argument("Power_Mod::set_base: arg must be > 0");

   if(!m_core)
      throw Internal_Error("Power_Mod::set_base: m_core was NULL");
   m_core->set_base(b);
   }

/*
* Set the exponent
*/
void Power_Mod::set_exponent(const BigInt& e) const
   {
   if(e.is_negative())
      throw Invalid_Argument("Power_Mod::set_exponent: arg must be > 0");

   if(!m_core)
      throw Internal_Error("Power_Mod::set_exponent: m_core was NULL");
   m_core->set_exponent(e);
   }

/*
* Compute the result
*/
BigInt Power_Mod::execute() const
   {
   if(!m_core)
      throw Internal_Error("Power_Mod::execute: m_core was NULL");
   return m_core->execute();
   }

/*
* Try to choose a good window size
*/
size_t Power_Mod::window_bits(size_t exp_bits, size_t,
                              Power_Mod::Usage_Hints hints)
   {
   static const size_t wsize[][2] = {
      { 1434, 7 },
      {  539, 6 },
      {  197, 4 },
      {   70, 3 },
      {   25, 2 },
      {    0, 0 }
   };

   size_t window_bits = 1;

   if(exp_bits)
      {
      for(size_t j = 0; wsize[j][0]; ++j)
         {
         if(exp_bits >= wsize[j][0])
            {
            window_bits += wsize[j][1];
            break;
            }
         }
      }

   if(hints & Power_Mod::BASE_IS_FIXED)
      window_bits += 2;
   if(hints & Power_Mod::EXP_IS_LARGE)
      ++window_bits;

   return window_bits;
   }

namespace {

/*
* Choose potentially useful hints
*/
Power_Mod::Usage_Hints choose_base_hints(const BigInt& b, const BigInt& n)
   {
   if(b == 2)
      return Power_Mod::Usage_Hints(Power_Mod::BASE_IS_2 |
                                    Power_Mod::BASE_IS_SMALL);

   const size_t b_bits = b.bits();
   const size_t n_bits = n.bits();

   if(b_bits < n_bits / 32)
      return Power_Mod::BASE_IS_SMALL;
   if(b_bits > n_bits / 4)
      return Power_Mod::BASE_IS_LARGE;

   return Power_Mod::NO_HINTS;
   }

/*
* Choose potentially useful hints
*/
Power_Mod::Usage_Hints choose_exp_hints(const BigInt& e, const BigInt& n)
   {
   const size_t e_bits = e.bits();
   const size_t n_bits = n.bits();

   if(e_bits < n_bits / 32)
      return Power_Mod::BASE_IS_SMALL;
   if(e_bits > n_bits / 4)
      return Power_Mod::BASE_IS_LARGE;
   return Power_Mod::NO_HINTS;
   }

}

/*
* Fixed_Exponent_Power_Mod Constructor
*/
Fixed_Exponent_Power_Mod::Fixed_Exponent_Power_Mod(const BigInt& e,
                                                   const BigInt& n,
                                                   Usage_Hints hints) :
   Power_Mod(n, Usage_Hints(hints | EXP_IS_FIXED | choose_exp_hints(e, n)))
   {
   set_exponent(e);
   }

/*
* Fixed_Base_Power_Mod Constructor
*/
Fixed_Base_Power_Mod::Fixed_Base_Power_Mod(const BigInt& b, const BigInt& n,
                                           Usage_Hints hints) :
   Power_Mod(n, Usage_Hints(hints | BASE_IS_FIXED | choose_base_hints(b, n)))
   {
   set_base(b);
   }

}
/*
* Fixed Window Exponentiation
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Set the exponent
*/
void Fixed_Window_Exponentiator::set_exponent(const BigInt& e)
   {
   m_exp = e;
   }

/*
* Set the base
*/
void Fixed_Window_Exponentiator::set_base(const BigInt& base)
   {
   m_window_bits = Power_Mod::window_bits(m_exp.bits(), base.bits(), m_hints);

   m_g.resize(1U << m_window_bits);
   m_g[0] = 1;
   m_g[1] = base;

   for(size_t i = 2; i != m_g.size(); ++i)
      m_g[i] = m_reducer.multiply(m_g[i-1], m_g[1]);
   }

/*
* Compute the result
*/
BigInt Fixed_Window_Exponentiator::execute() const
   {
   const size_t exp_nibbles = (m_exp.bits() + m_window_bits - 1) / m_window_bits;

   BigInt x = 1;

   for(size_t i = exp_nibbles; i > 0; --i)
      {
      for(size_t j = 0; j != m_window_bits; ++j)
         x = m_reducer.square(x);

      const uint32_t nibble = m_exp.get_substring(m_window_bits*(i-1), m_window_bits);

      x = m_reducer.multiply(x, m_g[nibble]);
      }
   return x;
   }

/*
* Fixed_Window_Exponentiator Constructor
*/
Fixed_Window_Exponentiator::Fixed_Window_Exponentiator(const BigInt& n,
                                                       Power_Mod::Usage_Hints hints)
      : m_reducer{Modular_Reducer(n)}, m_exp{}, m_window_bits{}, m_g{}, m_hints{hints}
   {}

}
/*
* Montgomery Exponentiation
* (C) 1999-2010,2012 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Set the exponent
*/
void Montgomery_Exponentiator::set_exponent(const BigInt& exp)
   {
   m_exp = exp;
   m_exp_bits = exp.bits();
   }

/*
* Set the base
*/
void Montgomery_Exponentiator::set_base(const BigInt& base)
   {
   m_window_bits = Power_Mod::window_bits(m_exp.bits(), base.bits(), m_hints);

   m_g.resize(1U << m_window_bits);

   BigInt z(BigInt::Positive, 2 * (m_mod_words + 1));
   secure_vector<word> workspace(z.size());

   m_g[0] = 1;

   bigint_monty_mul(z, m_g[0], m_R2_mod,
                    m_modulus.data(), m_mod_words, m_mod_prime,
                    workspace.data());
   m_g[0] = z;

   m_g[1] = m_reducer.reduce(base);

   bigint_monty_mul(z, m_g[1], m_R2_mod,
                    m_modulus.data(), m_mod_words, m_mod_prime,
                    workspace.data());

   m_g[1] = z;

   const BigInt& x = m_g[1];

   for(size_t i = 2; i != m_g.size(); ++i)
      {
      const BigInt& y = m_g[i-1];

      bigint_monty_mul(z, x, y, m_modulus.data(), m_mod_words, m_mod_prime,
                       workspace.data());

      m_g[i] = z;
      m_g[i].shrink_to_fit();
      m_g[i].grow_to(m_mod_words);
      }
   }

/*
* Compute the result
*/
BigInt Montgomery_Exponentiator::execute() const
   {
   const size_t exp_nibbles = (m_exp_bits + m_window_bits - 1) / m_window_bits;

   BigInt x = m_R_mod;

   const size_t z_size = 2*(m_mod_words + 1);

   BigInt z(BigInt::Positive, z_size);
   secure_vector<word> workspace(z.size());
   secure_vector<word> e(m_mod_words);

   for(size_t i = exp_nibbles; i > 0; --i)
      {
      for(size_t k = 0; k != m_window_bits; ++k)
         {
         bigint_monty_sqr(z, x, m_modulus.data(), m_mod_words, m_mod_prime,
                          workspace.data());

         x = z;
         }

      const uint32_t nibble = m_exp.get_substring(m_window_bits*(i-1), m_window_bits);

      BigInt::const_time_lookup(e, m_g, nibble);

      bigint_mul(z.mutable_data(), z.size(),
                 x.data(), x.size(), x.sig_words(),
                 e.data(), m_mod_words, m_mod_words,
                 workspace.data());

      bigint_monty_redc(z.mutable_data(),
                        m_modulus.data(), m_mod_words, m_mod_prime,
                        workspace.data());

      x = z;
      }

   x.grow_to(2*m_mod_words + 1);

   bigint_monty_redc(x.mutable_data(),
                     m_modulus.data(), m_mod_words, m_mod_prime,
                     workspace.data());

   return x;
   }

/*
* Montgomery_Exponentiator Constructor
*/
Montgomery_Exponentiator::Montgomery_Exponentiator(const BigInt& mod,
                                                   Power_Mod::Usage_Hints hints) :
   m_modulus(mod),
   m_reducer(m_modulus),
   m_mod_words(m_modulus.sig_words()),
   m_window_bits(1),
   m_hints(hints)
   {
   // Montgomery reduction only works for positive odd moduli
   if(!m_modulus.is_positive() || m_modulus.is_even())
      throw Invalid_Argument("Montgomery_Exponentiator: invalid modulus");

   m_mod_prime = monty_inverse(mod.word_at(0));

   const BigInt r = BigInt::power_of_2(m_mod_words * BOTAN_MP_WORD_BITS);
   m_R_mod = m_reducer.reduce(r);
   m_R2_mod = m_reducer.square(m_R_mod);
   m_exp_bits = 0;
   }

}
/*
* Small Primes Table
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

const uint16_t PRIMES[PRIME_TABLE_SIZE+1] = {
    3,     5,     7,    11,    13,    17,    19,    23,    29,    31,    37,
   41,    43,    47,    53,    59,    61,    67,    71,    73,    79,    83,
   89,    97,   101,   103,   107,   109,   113,   127,   131,   137,   139,
  149,   151,   157,   163,   167,   173,   179,   181,   191,   193,   197,
  199,   211,   223,   227,   229,   233,   239,   241,   251,   257,   263,
  269,   271,   277,   281,   283,   293,   307,   311,   313,   317,   331,
  337,   347,   349,   353,   359,   367,   373,   379,   383,   389,   397,
  401,   409,   419,   421,   431,   433,   439,   443,   449,   457,   461,
  463,   467,   479,   487,   491,   499,   503,   509,   521,   523,   541,
  547,   557,   563,   569,   571,   577,   587,   593,   599,   601,   607,
  613,   617,   619,   631,   641,   643,   647,   653,   659,   661,   673,
  677,   683,   691,   701,   709,   719,   727,   733,   739,   743,   751,
  757,   761,   769,   773,   787,   797,   809,   811,   821,   823,   827,
  829,   839,   853,   857,   859,   863,   877,   881,   883,   887,   907,
  911,   919,   929,   937,   941,   947,   953,   967,   971,   977,   983,
  991,   997,  1009,  1013,  1019,  1021,  1031,  1033,  1039,  1049,  1051,
 1061,  1063,  1069,  1087,  1091,  1093,  1097,  1103,  1109,  1117,  1123,
 1129,  1151,  1153,  1163,  1171,  1181,  1187,  1193,  1201,  1213,  1217,
 1223,  1229,  1231,  1237,  1249,  1259,  1277,  1279,  1283,  1289,  1291,
 1297,  1301,  1303,  1307,  1319,  1321,  1327,  1361,  1367,  1373,  1381,
 1399,  1409,  1423,  1427,  1429,  1433,  1439,  1447,  1451,  1453,  1459,
 1471,  1481,  1483,  1487,  1489,  1493,  1499,  1511,  1523,  1531,  1543,
 1549,  1553,  1559,  1567,  1571,  1579,  1583,  1597,  1601,  1607,  1609,
 1613,  1619,  1621,  1627,  1637,  1657,  1663,  1667,  1669,  1693,  1697,
 1699,  1709,  1721,  1723,  1733,  1741,  1747,  1753,  1759,  1777,  1783,
 1787,  1789,  1801,  1811,  1823,  1831,  1847,  1861,  1867,  1871,  1873,
 1877,  1879,  1889,  1901,  1907,  1913,  1931,  1933,  1949,  1951,  1973,
 1979,  1987,  1993,  1997,  1999,  2003,  2011,  2017,  2027,  2029,  2039,
 2053,  2063,  2069,  2081,  2083,  2087,  2089,  2099,  2111,  2113,  2129,
 2131,  2137,  2141,  2143,  2153,  2161,  2179,  2203,  2207,  2213,  2221,
 2237,  2239,  2243,  2251,  2267,  2269,  2273,  2281,  2287,  2293,  2297,
 2309,  2311,  2333,  2339,  2341,  2347,  2351,  2357,  2371,  2377,  2381,
 2383,  2389,  2393,  2399,  2411,  2417,  2423,  2437,  2441,  2447,  2459,
 2467,  2473,  2477,  2503,  2521,  2531,  2539,  2543,  2549,  2551,  2557,
 2579,  2591,  2593,  2609,  2617,  2621,  2633,  2647,  2657,  2659,  2663,
 2671,  2677,  2683,  2687,  2689,  2693,  2699,  2707,  2711,  2713,  2719,
 2729,  2731,  2741,  2749,  2753,  2767,  2777,  2789,  2791,  2797,  2801,
 2803,  2819,  2833,  2837,  2843,  2851,  2857,  2861,  2879,  2887,  2897,
 2903,  2909,  2917,  2927,  2939,  2953,  2957,  2963,  2969,  2971,  2999,
 3001,  3011,  3019,  3023,  3037,  3041,  3049,  3061,  3067,  3079,  3083,
 3089,  3109,  3119,  3121,  3137,  3163,  3167,  3169,  3181,  3187,  3191,
 3203,  3209,  3217,  3221,  3229,  3251,  3253,  3257,  3259,  3271,  3299,
 3301,  3307,  3313,  3319,  3323,  3329,  3331,  3343,  3347,  3359,  3361,
 3371,  3373,  3389,  3391,  3407,  3413,  3433,  3449,  3457,  3461,  3463,
 3467,  3469,  3491,  3499,  3511,  3517,  3527,  3529,  3533,  3539,  3541,
 3547,  3557,  3559,  3571,  3581,  3583,  3593,  3607,  3613,  3617,  3623,
 3631,  3637,  3643,  3659,  3671,  3673,  3677,  3691,  3697,  3701,  3709,
 3719,  3727,  3733,  3739,  3761,  3767,  3769,  3779,  3793,  3797,  3803,
 3821,  3823,  3833,  3847,  3851,  3853,  3863,  3877,  3881,  3889,  3907,
 3911,  3917,  3919,  3923,  3929,  3931,  3943,  3947,  3967,  3989,  4001,
 4003,  4007,  4013,  4019,  4021,  4027,  4049,  4051,  4057,  4073,  4079,
 4091,  4093,  4099,  4111,  4127,  4129,  4133,  4139,  4153,  4157,  4159,
 4177,  4201,  4211,  4217,  4219,  4229,  4231,  4241,  4243,  4253,  4259,
 4261,  4271,  4273,  4283,  4289,  4297,  4327,  4337,  4339,  4349,  4357,
 4363,  4373,  4391,  4397,  4409,  4421,  4423,  4441,  4447,  4451,  4457,
 4463,  4481,  4483,  4493,  4507,  4513,  4517,  4519,  4523,  4547,  4549,
 4561,  4567,  4583,  4591,  4597,  4603,  4621,  4637,  4639,  4643,  4649,
 4651,  4657,  4663,  4673,  4679,  4691,  4703,  4721,  4723,  4729,  4733,
 4751,  4759,  4783,  4787,  4789,  4793,  4799,  4801,  4813,  4817,  4831,
 4861,  4871,  4877,  4889,  4903,  4909,  4919,  4931,  4933,  4937,  4943,
 4951,  4957,  4967,  4969,  4973,  4987,  4993,  4999,  5003,  5009,  5011,
 5021,  5023,  5039,  5051,  5059,  5077,  5081,  5087,  5099,  5101,  5107,
 5113,  5119,  5147,  5153,  5167,  5171,  5179,  5189,  5197,  5209,  5227,
 5231,  5233,  5237,  5261,  5273,  5279,  5281,  5297,  5303,  5309,  5323,
 5333,  5347,  5351,  5381,  5387,  5393,  5399,  5407,  5413,  5417,  5419,
 5431,  5437,  5441,  5443,  5449,  5471,  5477,  5479,  5483,  5501,  5503,
 5507,  5519,  5521,  5527,  5531,  5557,  5563,  5569,  5573,  5581,  5591,
 5623,  5639,  5641,  5647,  5651,  5653,  5657,  5659,  5669,  5683,  5689,
 5693,  5701,  5711,  5717,  5737,  5741,  5743,  5749,  5779,  5783,  5791,
 5801,  5807,  5813,  5821,  5827,  5839,  5843,  5849,  5851,  5857,  5861,
 5867,  5869,  5879,  5881,  5897,  5903,  5923,  5927,  5939,  5953,  5981,
 5987,  6007,  6011,  6029,  6037,  6043,  6047,  6053,  6067,  6073,  6079,
 6089,  6091,  6101,  6113,  6121,  6131,  6133,  6143,  6151,  6163,  6173,
 6197,  6199,  6203,  6211,  6217,  6221,  6229,  6247,  6257,  6263,  6269,
 6271,  6277,  6287,  6299,  6301,  6311,  6317,  6323,  6329,  6337,  6343,
 6353,  6359,  6361,  6367,  6373,  6379,  6389,  6397,  6421,  6427,  6449,
 6451,  6469,  6473,  6481,  6491,  6521,  6529,  6547,  6551,  6553,  6563,
 6569,  6571,  6577,  6581,  6599,  6607,  6619,  6637,  6653,  6659,  6661,
 6673,  6679,  6689,  6691,  6701,  6703,  6709,  6719,  6733,  6737,  6761,
 6763,  6779,  6781,  6791,  6793,  6803,  6823,  6827,  6829,  6833,  6841,
 6857,  6863,  6869,  6871,  6883,  6899,  6907,  6911,  6917,  6947,  6949,
 6959,  6961,  6967,  6971,  6977,  6983,  6991,  6997,  7001,  7013,  7019,
 7027,  7039,  7043,  7057,  7069,  7079,  7103,  7109,  7121,  7127,  7129,
 7151,  7159,  7177,  7187,  7193,  7207,  7211,  7213,  7219,  7229,  7237,
 7243,  7247,  7253,  7283,  7297,  7307,  7309,  7321,  7331,  7333,  7349,
 7351,  7369,  7393,  7411,  7417,  7433,  7451,  7457,  7459,  7477,  7481,
 7487,  7489,  7499,  7507,  7517,  7523,  7529,  7537,  7541,  7547,  7549,
 7559,  7561,  7573,  7577,  7583,  7589,  7591,  7603,  7607,  7621,  7639,
 7643,  7649,  7669,  7673,  7681,  7687,  7691,  7699,  7703,  7717,  7723,
 7727,  7741,  7753,  7757,  7759,  7789,  7793,  7817,  7823,  7829,  7841,
 7853,  7867,  7873,  7877,  7879,  7883,  7901,  7907,  7919,  7927,  7933,
 7937,  7949,  7951,  7963,  7993,  8009,  8011,  8017,  8039,  8053,  8059,
 8069,  8081,  8087,  8089,  8093,  8101,  8111,  8117,  8123,  8147,  8161,
 8167,  8171,  8179,  8191,  8209,  8219,  8221,  8231,  8233,  8237,  8243,
 8263,  8269,  8273,  8287,  8291,  8293,  8297,  8311,  8317,  8329,  8353,
 8363,  8369,  8377,  8387,  8389,  8419,  8423,  8429,  8431,  8443,  8447,
 8461,  8467,  8501,  8513,  8521,  8527,  8537,  8539,  8543,  8563,  8573,
 8581,  8597,  8599,  8609,  8623,  8627,  8629,  8641,  8647,  8663,  8669,
 8677,  8681,  8689,  8693,  8699,  8707,  8713,  8719,  8731,  8737,  8741,
 8747,  8753,  8761,  8779,  8783,  8803,  8807,  8819,  8821,  8831,  8837,
 8839,  8849,  8861,  8863,  8867,  8887,  8893,  8923,  8929,  8933,  8941,
 8951,  8963,  8969,  8971,  8999,  9001,  9007,  9011,  9013,  9029,  9041,
 9043,  9049,  9059,  9067,  9091,  9103,  9109,  9127,  9133,  9137,  9151,
 9157,  9161,  9173,  9181,  9187,  9199,  9203,  9209,  9221,  9227,  9239,
 9241,  9257,  9277,  9281,  9283,  9293,  9311,  9319,  9323,  9337,  9341,
 9343,  9349,  9371,  9377,  9391,  9397,  9403,  9413,  9419,  9421,  9431,
 9433,  9437,  9439,  9461,  9463,  9467,  9473,  9479,  9491,  9497,  9511,
 9521,  9533,  9539,  9547,  9551,  9587,  9601,  9613,  9619,  9623,  9629,
 9631,  9643,  9649,  9661,  9677,  9679,  9689,  9697,  9719,  9721,  9733,
 9739,  9743,  9749,  9767,  9769,  9781,  9787,  9791,  9803,  9811,  9817,
 9829,  9833,  9839,  9851,  9857,  9859,  9871,  9883,  9887,  9901,  9907,
 9923,  9929,  9931,  9941,  9949,  9967,  9973, 10007, 10009, 10037, 10039,
10061, 10067, 10069, 10079, 10091, 10093, 10099, 10103, 10111, 10133, 10139,
10141, 10151, 10159, 10163, 10169, 10177, 10181, 10193, 10211, 10223, 10243,
10247, 10253, 10259, 10267, 10271, 10273, 10289, 10301, 10303, 10313, 10321,
10331, 10333, 10337, 10343, 10357, 10369, 10391, 10399, 10427, 10429, 10433,
10453, 10457, 10459, 10463, 10477, 10487, 10499, 10501, 10513, 10529, 10531,
10559, 10567, 10589, 10597, 10601, 10607, 10613, 10627, 10631, 10639, 10651,
10657, 10663, 10667, 10687, 10691, 10709, 10711, 10723, 10729, 10733, 10739,
10753, 10771, 10781, 10789, 10799, 10831, 10837, 10847, 10853, 10859, 10861,
10867, 10883, 10889, 10891, 10903, 10909, 10937, 10939, 10949, 10957, 10973,
10979, 10987, 10993, 11003, 11027, 11047, 11057, 11059, 11069, 11071, 11083,
11087, 11093, 11113, 11117, 11119, 11131, 11149, 11159, 11161, 11171, 11173,
11177, 11197, 11213, 11239, 11243, 11251, 11257, 11261, 11273, 11279, 11287,
11299, 11311, 11317, 11321, 11329, 11351, 11353, 11369, 11383, 11393, 11399,
11411, 11423, 11437, 11443, 11447, 11467, 11471, 11483, 11489, 11491, 11497,
11503, 11519, 11527, 11549, 11551, 11579, 11587, 11593, 11597, 11617, 11621,
11633, 11657, 11677, 11681, 11689, 11699, 11701, 11717, 11719, 11731, 11743,
11777, 11779, 11783, 11789, 11801, 11807, 11813, 11821, 11827, 11831, 11833,
11839, 11863, 11867, 11887, 11897, 11903, 11909, 11923, 11927, 11933, 11939,
11941, 11953, 11959, 11969, 11971, 11981, 11987, 12007, 12011, 12037, 12041,
12043, 12049, 12071, 12073, 12097, 12101, 12107, 12109, 12113, 12119, 12143,
12149, 12157, 12161, 12163, 12197, 12203, 12211, 12227, 12239, 12241, 12251,
12253, 12263, 12269, 12277, 12281, 12289, 12301, 12323, 12329, 12343, 12347,
12373, 12377, 12379, 12391, 12401, 12409, 12413, 12421, 12433, 12437, 12451,
12457, 12473, 12479, 12487, 12491, 12497, 12503, 12511, 12517, 12527, 12539,
12541, 12547, 12553, 12569, 12577, 12583, 12589, 12601, 12611, 12613, 12619,
12637, 12641, 12647, 12653, 12659, 12671, 12689, 12697, 12703, 12713, 12721,
12739, 12743, 12757, 12763, 12781, 12791, 12799, 12809, 12821, 12823, 12829,
12841, 12853, 12889, 12893, 12899, 12907, 12911, 12917, 12919, 12923, 12941,
12953, 12959, 12967, 12973, 12979, 12983, 13001, 13003, 13007, 13009, 13033,
13037, 13043, 13049, 13063, 13093, 13099, 13103, 13109, 13121, 13127, 13147,
13151, 13159, 13163, 13171, 13177, 13183, 13187, 13217, 13219, 13229, 13241,
13249, 13259, 13267, 13291, 13297, 13309, 13313, 13327, 13331, 13337, 13339,
13367, 13381, 13397, 13399, 13411, 13417, 13421, 13441, 13451, 13457, 13463,
13469, 13477, 13487, 13499, 13513, 13523, 13537, 13553, 13567, 13577, 13591,
13597, 13613, 13619, 13627, 13633, 13649, 13669, 13679, 13681, 13687, 13691,
13693, 13697, 13709, 13711, 13721, 13723, 13729, 13751, 13757, 13759, 13763,
13781, 13789, 13799, 13807, 13829, 13831, 13841, 13859, 13873, 13877, 13879,
13883, 13901, 13903, 13907, 13913, 13921, 13931, 13933, 13963, 13967, 13997,
13999, 14009, 14011, 14029, 14033, 14051, 14057, 14071, 14081, 14083, 14087,
14107, 14143, 14149, 14153, 14159, 14173, 14177, 14197, 14207, 14221, 14243,
14249, 14251, 14281, 14293, 14303, 14321, 14323, 14327, 14341, 14347, 14369,
14387, 14389, 14401, 14407, 14411, 14419, 14423, 14431, 14437, 14447, 14449,
14461, 14479, 14489, 14503, 14519, 14533, 14537, 14543, 14549, 14551, 14557,
14561, 14563, 14591, 14593, 14621, 14627, 14629, 14633, 14639, 14653, 14657,
14669, 14683, 14699, 14713, 14717, 14723, 14731, 14737, 14741, 14747, 14753,
14759, 14767, 14771, 14779, 14783, 14797, 14813, 14821, 14827, 14831, 14843,
14851, 14867, 14869, 14879, 14887, 14891, 14897, 14923, 14929, 14939, 14947,
14951, 14957, 14969, 14983, 15013, 15017, 15031, 15053, 15061, 15073, 15077,
15083, 15091, 15101, 15107, 15121, 15131, 15137, 15139, 15149, 15161, 15173,
15187, 15193, 15199, 15217, 15227, 15233, 15241, 15259, 15263, 15269, 15271,
15277, 15287, 15289, 15299, 15307, 15313, 15319, 15329, 15331, 15349, 15359,
15361, 15373, 15377, 15383, 15391, 15401, 15413, 15427, 15439, 15443, 15451,
15461, 15467, 15473, 15493, 15497, 15511, 15527, 15541, 15551, 15559, 15569,
15581, 15583, 15601, 15607, 15619, 15629, 15641, 15643, 15647, 15649, 15661,
15667, 15671, 15679, 15683, 15727, 15731, 15733, 15737, 15739, 15749, 15761,
15767, 15773, 15787, 15791, 15797, 15803, 15809, 15817, 15823, 15859, 15877,
15881, 15887, 15889, 15901, 15907, 15913, 15919, 15923, 15937, 15959, 15971,
15973, 15991, 16001, 16007, 16033, 16057, 16061, 16063, 16067, 16069, 16073,
16087, 16091, 16097, 16103, 16111, 16127, 16139, 16141, 16183, 16187, 16189,
16193, 16217, 16223, 16229, 16231, 16249, 16253, 16267, 16273, 16301, 16319,
16333, 16339, 16349, 16361, 16363, 16369, 16381, 16411, 16417, 16421, 16427,
16433, 16447, 16451, 16453, 16477, 16481, 16487, 16493, 16519, 16529, 16547,
16553, 16561, 16567, 16573, 16603, 16607, 16619, 16631, 16633, 16649, 16651,
16657, 16661, 16673, 16691, 16693, 16699, 16703, 16729, 16741, 16747, 16759,
16763, 16787, 16811, 16823, 16829, 16831, 16843, 16871, 16879, 16883, 16889,
16901, 16903, 16921, 16927, 16931, 16937, 16943, 16963, 16979, 16981, 16987,
16993, 17011, 17021, 17027, 17029, 17033, 17041, 17047, 17053, 17077, 17093,
17099, 17107, 17117, 17123, 17137, 17159, 17167, 17183, 17189, 17191, 17203,
17207, 17209, 17231, 17239, 17257, 17291, 17293, 17299, 17317, 17321, 17327,
17333, 17341, 17351, 17359, 17377, 17383, 17387, 17389, 17393, 17401, 17417,
17419, 17431, 17443, 17449, 17467, 17471, 17477, 17483, 17489, 17491, 17497,
17509, 17519, 17539, 17551, 17569, 17573, 17579, 17581, 17597, 17599, 17609,
17623, 17627, 17657, 17659, 17669, 17681, 17683, 17707, 17713, 17729, 17737,
17747, 17749, 17761, 17783, 17789, 17791, 17807, 17827, 17837, 17839, 17851,
17863, 17881, 17891, 17903, 17909, 17911, 17921, 17923, 17929, 17939, 17957,
17959, 17971, 17977, 17981, 17987, 17989, 18013, 18041, 18043, 18047, 18049,
18059, 18061, 18077, 18089, 18097, 18119, 18121, 18127, 18131, 18133, 18143,
18149, 18169, 18181, 18191, 18199, 18211, 18217, 18223, 18229, 18233, 18251,
18253, 18257, 18269, 18287, 18289, 18301, 18307, 18311, 18313, 18329, 18341,
18353, 18367, 18371, 18379, 18397, 18401, 18413, 18427, 18433, 18439, 18443,
18451, 18457, 18461, 18481, 18493, 18503, 18517, 18521, 18523, 18539, 18541,
18553, 18583, 18587, 18593, 18617, 18637, 18661, 18671, 18679, 18691, 18701,
18713, 18719, 18731, 18743, 18749, 18757, 18773, 18787, 18793, 18797, 18803,
18839, 18859, 18869, 18899, 18911, 18913, 18917, 18919, 18947, 18959, 18973,
18979, 19001, 19009, 19013, 19031, 19037, 19051, 19069, 19073, 19079, 19081,
19087, 19121, 19139, 19141, 19157, 19163, 19181, 19183, 19207, 19211, 19213,
19219, 19231, 19237, 19249, 19259, 19267, 19273, 19289, 19301, 19309, 19319,
19333, 19373, 19379, 19381, 19387, 19391, 19403, 19417, 19421, 19423, 19427,
19429, 19433, 19441, 19447, 19457, 19463, 19469, 19471, 19477, 19483, 19489,
19501, 19507, 19531, 19541, 19543, 19553, 19559, 19571, 19577, 19583, 19597,
19603, 19609, 19661, 19681, 19687, 19697, 19699, 19709, 19717, 19727, 19739,
19751, 19753, 19759, 19763, 19777, 19793, 19801, 19813, 19819, 19841, 19843,
19853, 19861, 19867, 19889, 19891, 19913, 19919, 19927, 19937, 19949, 19961,
19963, 19973, 19979, 19991, 19993, 19997, 20011, 20021, 20023, 20029, 20047,
20051, 20063, 20071, 20089, 20101, 20107, 20113, 20117, 20123, 20129, 20143,
20147, 20149, 20161, 20173, 20177, 20183, 20201, 20219, 20231, 20233, 20249,
20261, 20269, 20287, 20297, 20323, 20327, 20333, 20341, 20347, 20353, 20357,
20359, 20369, 20389, 20393, 20399, 20407, 20411, 20431, 20441, 20443, 20477,
20479, 20483, 20507, 20509, 20521, 20533, 20543, 20549, 20551, 20563, 20593,
20599, 20611, 20627, 20639, 20641, 20663, 20681, 20693, 20707, 20717, 20719,
20731, 20743, 20747, 20749, 20753, 20759, 20771, 20773, 20789, 20807, 20809,
20849, 20857, 20873, 20879, 20887, 20897, 20899, 20903, 20921, 20929, 20939,
20947, 20959, 20963, 20981, 20983, 21001, 21011, 21013, 21017, 21019, 21023,
21031, 21059, 21061, 21067, 21089, 21101, 21107, 21121, 21139, 21143, 21149,
21157, 21163, 21169, 21179, 21187, 21191, 21193, 21211, 21221, 21227, 21247,
21269, 21277, 21283, 21313, 21317, 21319, 21323, 21341, 21347, 21377, 21379,
21383, 21391, 21397, 21401, 21407, 21419, 21433, 21467, 21481, 21487, 21491,
21493, 21499, 21503, 21517, 21521, 21523, 21529, 21557, 21559, 21563, 21569,
21577, 21587, 21589, 21599, 21601, 21611, 21613, 21617, 21647, 21649, 21661,
21673, 21683, 21701, 21713, 21727, 21737, 21739, 21751, 21757, 21767, 21773,
21787, 21799, 21803, 21817, 21821, 21839, 21841, 21851, 21859, 21863, 21871,
21881, 21893, 21911, 21929, 21937, 21943, 21961, 21977, 21991, 21997, 22003,
22013, 22027, 22031, 22037, 22039, 22051, 22063, 22067, 22073, 22079, 22091,
22093, 22109, 22111, 22123, 22129, 22133, 22147, 22153, 22157, 22159, 22171,
22189, 22193, 22229, 22247, 22259, 22271, 22273, 22277, 22279, 22283, 22291,
22303, 22307, 22343, 22349, 22367, 22369, 22381, 22391, 22397, 22409, 22433,
22441, 22447, 22453, 22469, 22481, 22483, 22501, 22511, 22531, 22541, 22543,
22549, 22567, 22571, 22573, 22613, 22619, 22621, 22637, 22639, 22643, 22651,
22669, 22679, 22691, 22697, 22699, 22709, 22717, 22721, 22727, 22739, 22741,
22751, 22769, 22777, 22783, 22787, 22807, 22811, 22817, 22853, 22859, 22861,
22871, 22877, 22901, 22907, 22921, 22937, 22943, 22961, 22963, 22973, 22993,
23003, 23011, 23017, 23021, 23027, 23029, 23039, 23041, 23053, 23057, 23059,
23063, 23071, 23081, 23087, 23099, 23117, 23131, 23143, 23159, 23167, 23173,
23189, 23197, 23201, 23203, 23209, 23227, 23251, 23269, 23279, 23291, 23293,
23297, 23311, 23321, 23327, 23333, 23339, 23357, 23369, 23371, 23399, 23417,
23431, 23447, 23459, 23473, 23497, 23509, 23531, 23537, 23539, 23549, 23557,
23561, 23563, 23567, 23581, 23593, 23599, 23603, 23609, 23623, 23627, 23629,
23633, 23663, 23669, 23671, 23677, 23687, 23689, 23719, 23741, 23743, 23747,
23753, 23761, 23767, 23773, 23789, 23801, 23813, 23819, 23827, 23831, 23833,
23857, 23869, 23873, 23879, 23887, 23893, 23899, 23909, 23911, 23917, 23929,
23957, 23971, 23977, 23981, 23993, 24001, 24007, 24019, 24023, 24029, 24043,
24049, 24061, 24071, 24077, 24083, 24091, 24097, 24103, 24107, 24109, 24113,
24121, 24133, 24137, 24151, 24169, 24179, 24181, 24197, 24203, 24223, 24229,
24239, 24247, 24251, 24281, 24317, 24329, 24337, 24359, 24371, 24373, 24379,
24391, 24407, 24413, 24419, 24421, 24439, 24443, 24469, 24473, 24481, 24499,
24509, 24517, 24527, 24533, 24547, 24551, 24571, 24593, 24611, 24623, 24631,
24659, 24671, 24677, 24683, 24691, 24697, 24709, 24733, 24749, 24763, 24767,
24781, 24793, 24799, 24809, 24821, 24841, 24847, 24851, 24859, 24877, 24889,
24907, 24917, 24919, 24923, 24943, 24953, 24967, 24971, 24977, 24979, 24989,
25013, 25031, 25033, 25037, 25057, 25073, 25087, 25097, 25111, 25117, 25121,
25127, 25147, 25153, 25163, 25169, 25171, 25183, 25189, 25219, 25229, 25237,
25243, 25247, 25253, 25261, 25301, 25303, 25307, 25309, 25321, 25339, 25343,
25349, 25357, 25367, 25373, 25391, 25409, 25411, 25423, 25439, 25447, 25453,
25457, 25463, 25469, 25471, 25523, 25537, 25541, 25561, 25577, 25579, 25583,
25589, 25601, 25603, 25609, 25621, 25633, 25639, 25643, 25657, 25667, 25673,
25679, 25693, 25703, 25717, 25733, 25741, 25747, 25759, 25763, 25771, 25793,
25799, 25801, 25819, 25841, 25847, 25849, 25867, 25873, 25889, 25903, 25913,
25919, 25931, 25933, 25939, 25943, 25951, 25969, 25981, 25997, 25999, 26003,
26017, 26021, 26029, 26041, 26053, 26083, 26099, 26107, 26111, 26113, 26119,
26141, 26153, 26161, 26171, 26177, 26183, 26189, 26203, 26209, 26227, 26237,
26249, 26251, 26261, 26263, 26267, 26293, 26297, 26309, 26317, 26321, 26339,
26347, 26357, 26371, 26387, 26393, 26399, 26407, 26417, 26423, 26431, 26437,
26449, 26459, 26479, 26489, 26497, 26501, 26513, 26539, 26557, 26561, 26573,
26591, 26597, 26627, 26633, 26641, 26647, 26669, 26681, 26683, 26687, 26693,
26699, 26701, 26711, 26713, 26717, 26723, 26729, 26731, 26737, 26759, 26777,
26783, 26801, 26813, 26821, 26833, 26839, 26849, 26861, 26863, 26879, 26881,
26891, 26893, 26903, 26921, 26927, 26947, 26951, 26953, 26959, 26981, 26987,
26993, 27011, 27017, 27031, 27043, 27059, 27061, 27067, 27073, 27077, 27091,
27103, 27107, 27109, 27127, 27143, 27179, 27191, 27197, 27211, 27239, 27241,
27253, 27259, 27271, 27277, 27281, 27283, 27299, 27329, 27337, 27361, 27367,
27397, 27407, 27409, 27427, 27431, 27437, 27449, 27457, 27479, 27481, 27487,
27509, 27527, 27529, 27539, 27541, 27551, 27581, 27583, 27611, 27617, 27631,
27647, 27653, 27673, 27689, 27691, 27697, 27701, 27733, 27737, 27739, 27743,
27749, 27751, 27763, 27767, 27773, 27779, 27791, 27793, 27799, 27803, 27809,
27817, 27823, 27827, 27847, 27851, 27883, 27893, 27901, 27917, 27919, 27941,
27943, 27947, 27953, 27961, 27967, 27983, 27997, 28001, 28019, 28027, 28031,
28051, 28057, 28069, 28081, 28087, 28097, 28099, 28109, 28111, 28123, 28151,
28163, 28181, 28183, 28201, 28211, 28219, 28229, 28277, 28279, 28283, 28289,
28297, 28307, 28309, 28319, 28349, 28351, 28387, 28393, 28403, 28409, 28411,
28429, 28433, 28439, 28447, 28463, 28477, 28493, 28499, 28513, 28517, 28537,
28541, 28547, 28549, 28559, 28571, 28573, 28579, 28591, 28597, 28603, 28607,
28619, 28621, 28627, 28631, 28643, 28649, 28657, 28661, 28663, 28669, 28687,
28697, 28703, 28711, 28723, 28729, 28751, 28753, 28759, 28771, 28789, 28793,
28807, 28813, 28817, 28837, 28843, 28859, 28867, 28871, 28879, 28901, 28909,
28921, 28927, 28933, 28949, 28961, 28979, 29009, 29017, 29021, 29023, 29027,
29033, 29059, 29063, 29077, 29101, 29123, 29129, 29131, 29137, 29147, 29153,
29167, 29173, 29179, 29191, 29201, 29207, 29209, 29221, 29231, 29243, 29251,
29269, 29287, 29297, 29303, 29311, 29327, 29333, 29339, 29347, 29363, 29383,
29387, 29389, 29399, 29401, 29411, 29423, 29429, 29437, 29443, 29453, 29473,
29483, 29501, 29527, 29531, 29537, 29567, 29569, 29573, 29581, 29587, 29599,
29611, 29629, 29633, 29641, 29663, 29669, 29671, 29683, 29717, 29723, 29741,
29753, 29759, 29761, 29789, 29803, 29819, 29833, 29837, 29851, 29863, 29867,
29873, 29879, 29881, 29917, 29921, 29927, 29947, 29959, 29983, 29989, 30011,
30013, 30029, 30047, 30059, 30071, 30089, 30091, 30097, 30103, 30109, 30113,
30119, 30133, 30137, 30139, 30161, 30169, 30181, 30187, 30197, 30203, 30211,
30223, 30241, 30253, 30259, 30269, 30271, 30293, 30307, 30313, 30319, 30323,
30341, 30347, 30367, 30389, 30391, 30403, 30427, 30431, 30449, 30467, 30469,
30491, 30493, 30497, 30509, 30517, 30529, 30539, 30553, 30557, 30559, 30577,
30593, 30631, 30637, 30643, 30649, 30661, 30671, 30677, 30689, 30697, 30703,
30707, 30713, 30727, 30757, 30763, 30773, 30781, 30803, 30809, 30817, 30829,
30839, 30841, 30851, 30853, 30859, 30869, 30871, 30881, 30893, 30911, 30931,
30937, 30941, 30949, 30971, 30977, 30983, 31013, 31019, 31033, 31039, 31051,
31063, 31069, 31079, 31081, 31091, 31121, 31123, 31139, 31147, 31151, 31153,
31159, 31177, 31181, 31183, 31189, 31193, 31219, 31223, 31231, 31237, 31247,
31249, 31253, 31259, 31267, 31271, 31277, 31307, 31319, 31321, 31327, 31333,
31337, 31357, 31379, 31387, 31391, 31393, 31397, 31469, 31477, 31481, 31489,
31511, 31513, 31517, 31531, 31541, 31543, 31547, 31567, 31573, 31583, 31601,
31607, 31627, 31643, 31649, 31657, 31663, 31667, 31687, 31699, 31721, 31723,
31727, 31729, 31741, 31751, 31769, 31771, 31793, 31799, 31817, 31847, 31849,
31859, 31873, 31883, 31891, 31907, 31957, 31963, 31973, 31981, 31991, 32003,
32009, 32027, 32029, 32051, 32057, 32059, 32063, 32069, 32077, 32083, 32089,
32099, 32117, 32119, 32141, 32143, 32159, 32173, 32183, 32189, 32191, 32203,
32213, 32233, 32237, 32251, 32257, 32261, 32297, 32299, 32303, 32309, 32321,
32323, 32327, 32341, 32353, 32359, 32363, 32369, 32371, 32377, 32381, 32401,
32411, 32413, 32423, 32429, 32441, 32443, 32467, 32479, 32491, 32497, 32503,
32507, 32531, 32533, 32537, 32561, 32563, 32569, 32573, 32579, 32587, 32603,
32609, 32611, 32621, 32633, 32647, 32653, 32687, 32693, 32707, 32713, 32717,
32719, 32749, 32771, 32779, 32783, 32789, 32797, 32801, 32803, 32831, 32833,
32839, 32843, 32869, 32887, 32909, 32911, 32917, 32933, 32939, 32941, 32957,
32969, 32971, 32983, 32987, 32993, 32999, 33013, 33023, 33029, 33037, 33049,
33053, 33071, 33073, 33083, 33091, 33107, 33113, 33119, 33149, 33151, 33161,
33179, 33181, 33191, 33199, 33203, 33211, 33223, 33247, 33287, 33289, 33301,
33311, 33317, 33329, 33331, 33343, 33347, 33349, 33353, 33359, 33377, 33391,
33403, 33409, 33413, 33427, 33457, 33461, 33469, 33479, 33487, 33493, 33503,
33521, 33529, 33533, 33547, 33563, 33569, 33577, 33581, 33587, 33589, 33599,
33601, 33613, 33617, 33619, 33623, 33629, 33637, 33641, 33647, 33679, 33703,
33713, 33721, 33739, 33749, 33751, 33757, 33767, 33769, 33773, 33791, 33797,
33809, 33811, 33827, 33829, 33851, 33857, 33863, 33871, 33889, 33893, 33911,
33923, 33931, 33937, 33941, 33961, 33967, 33997, 34019, 34031, 34033, 34039,
34057, 34061, 34123, 34127, 34129, 34141, 34147, 34157, 34159, 34171, 34183,
34211, 34213, 34217, 34231, 34253, 34259, 34261, 34267, 34273, 34283, 34297,
34301, 34303, 34313, 34319, 34327, 34337, 34351, 34361, 34367, 34369, 34381,
34403, 34421, 34429, 34439, 34457, 34469, 34471, 34483, 34487, 34499, 34501,
34511, 34513, 34519, 34537, 34543, 34549, 34583, 34589, 34591, 34603, 34607,
34613, 34631, 34649, 34651, 34667, 34673, 34679, 34687, 34693, 34703, 34721,
34729, 34739, 34747, 34757, 34759, 34763, 34781, 34807, 34819, 34841, 34843,
34847, 34849, 34871, 34877, 34883, 34897, 34913, 34919, 34939, 34949, 34961,
34963, 34981, 35023, 35027, 35051, 35053, 35059, 35069, 35081, 35083, 35089,
35099, 35107, 35111, 35117, 35129, 35141, 35149, 35153, 35159, 35171, 35201,
35221, 35227, 35251, 35257, 35267, 35279, 35281, 35291, 35311, 35317, 35323,
35327, 35339, 35353, 35363, 35381, 35393, 35401, 35407, 35419, 35423, 35437,
35447, 35449, 35461, 35491, 35507, 35509, 35521, 35527, 35531, 35533, 35537,
35543, 35569, 35573, 35591, 35593, 35597, 35603, 35617, 35671, 35677, 35729,
35731, 35747, 35753, 35759, 35771, 35797, 35801, 35803, 35809, 35831, 35837,
35839, 35851, 35863, 35869, 35879, 35897, 35899, 35911, 35923, 35933, 35951,
35963, 35969, 35977, 35983, 35993, 35999, 36007, 36011, 36013, 36017, 36037,
36061, 36067, 36073, 36083, 36097, 36107, 36109, 36131, 36137, 36151, 36161,
36187, 36191, 36209, 36217, 36229, 36241, 36251, 36263, 36269, 36277, 36293,
36299, 36307, 36313, 36319, 36341, 36343, 36353, 36373, 36383, 36389, 36433,
36451, 36457, 36467, 36469, 36473, 36479, 36493, 36497, 36523, 36527, 36529,
36541, 36551, 36559, 36563, 36571, 36583, 36587, 36599, 36607, 36629, 36637,
36643, 36653, 36671, 36677, 36683, 36691, 36697, 36709, 36713, 36721, 36739,
36749, 36761, 36767, 36779, 36781, 36787, 36791, 36793, 36809, 36821, 36833,
36847, 36857, 36871, 36877, 36887, 36899, 36901, 36913, 36919, 36923, 36929,
36931, 36943, 36947, 36973, 36979, 36997, 37003, 37013, 37019, 37021, 37039,
37049, 37057, 37061, 37087, 37097, 37117, 37123, 37139, 37159, 37171, 37181,
37189, 37199, 37201, 37217, 37223, 37243, 37253, 37273, 37277, 37307, 37309,
37313, 37321, 37337, 37339, 37357, 37361, 37363, 37369, 37379, 37397, 37409,
37423, 37441, 37447, 37463, 37483, 37489, 37493, 37501, 37507, 37511, 37517,
37529, 37537, 37547, 37549, 37561, 37567, 37571, 37573, 37579, 37589, 37591,
37607, 37619, 37633, 37643, 37649, 37657, 37663, 37691, 37693, 37699, 37717,
37747, 37781, 37783, 37799, 37811, 37813, 37831, 37847, 37853, 37861, 37871,
37879, 37889, 37897, 37907, 37951, 37957, 37963, 37967, 37987, 37991, 37993,
37997, 38011, 38039, 38047, 38053, 38069, 38083, 38113, 38119, 38149, 38153,
38167, 38177, 38183, 38189, 38197, 38201, 38219, 38231, 38237, 38239, 38261,
38273, 38281, 38287, 38299, 38303, 38317, 38321, 38327, 38329, 38333, 38351,
38371, 38377, 38393, 38431, 38447, 38449, 38453, 38459, 38461, 38501, 38543,
38557, 38561, 38567, 38569, 38593, 38603, 38609, 38611, 38629, 38639, 38651,
38653, 38669, 38671, 38677, 38693, 38699, 38707, 38711, 38713, 38723, 38729,
38737, 38747, 38749, 38767, 38783, 38791, 38803, 38821, 38833, 38839, 38851,
38861, 38867, 38873, 38891, 38903, 38917, 38921, 38923, 38933, 38953, 38959,
38971, 38977, 38993, 39019, 39023, 39041, 39043, 39047, 39079, 39089, 39097,
39103, 39107, 39113, 39119, 39133, 39139, 39157, 39161, 39163, 39181, 39191,
39199, 39209, 39217, 39227, 39229, 39233, 39239, 39241, 39251, 39293, 39301,
39313, 39317, 39323, 39341, 39343, 39359, 39367, 39371, 39373, 39383, 39397,
39409, 39419, 39439, 39443, 39451, 39461, 39499, 39503, 39509, 39511, 39521,
39541, 39551, 39563, 39569, 39581, 39607, 39619, 39623, 39631, 39659, 39667,
39671, 39679, 39703, 39709, 39719, 39727, 39733, 39749, 39761, 39769, 39779,
39791, 39799, 39821, 39827, 39829, 39839, 39841, 39847, 39857, 39863, 39869,
39877, 39883, 39887, 39901, 39929, 39937, 39953, 39971, 39979, 39983, 39989,
40009, 40013, 40031, 40037, 40039, 40063, 40087, 40093, 40099, 40111, 40123,
40127, 40129, 40151, 40153, 40163, 40169, 40177, 40189, 40193, 40213, 40231,
40237, 40241, 40253, 40277, 40283, 40289, 40343, 40351, 40357, 40361, 40387,
40423, 40427, 40429, 40433, 40459, 40471, 40483, 40487, 40493, 40499, 40507,
40519, 40529, 40531, 40543, 40559, 40577, 40583, 40591, 40597, 40609, 40627,
40637, 40639, 40693, 40697, 40699, 40709, 40739, 40751, 40759, 40763, 40771,
40787, 40801, 40813, 40819, 40823, 40829, 40841, 40847, 40849, 40853, 40867,
40879, 40883, 40897, 40903, 40927, 40933, 40939, 40949, 40961, 40973, 40993,
41011, 41017, 41023, 41039, 41047, 41051, 41057, 41077, 41081, 41113, 41117,
41131, 41141, 41143, 41149, 41161, 41177, 41179, 41183, 41189, 41201, 41203,
41213, 41221, 41227, 41231, 41233, 41243, 41257, 41263, 41269, 41281, 41299,
41333, 41341, 41351, 41357, 41381, 41387, 41389, 41399, 41411, 41413, 41443,
41453, 41467, 41479, 41491, 41507, 41513, 41519, 41521, 41539, 41543, 41549,
41579, 41593, 41597, 41603, 41609, 41611, 41617, 41621, 41627, 41641, 41647,
41651, 41659, 41669, 41681, 41687, 41719, 41729, 41737, 41759, 41761, 41771,
41777, 41801, 41809, 41813, 41843, 41849, 41851, 41863, 41879, 41887, 41893,
41897, 41903, 41911, 41927, 41941, 41947, 41953, 41957, 41959, 41969, 41981,
41983, 41999, 42013, 42017, 42019, 42023, 42043, 42061, 42071, 42073, 42083,
42089, 42101, 42131, 42139, 42157, 42169, 42179, 42181, 42187, 42193, 42197,
42209, 42221, 42223, 42227, 42239, 42257, 42281, 42283, 42293, 42299, 42307,
42323, 42331, 42337, 42349, 42359, 42373, 42379, 42391, 42397, 42403, 42407,
42409, 42433, 42437, 42443, 42451, 42457, 42461, 42463, 42467, 42473, 42487,
42491, 42499, 42509, 42533, 42557, 42569, 42571, 42577, 42589, 42611, 42641,
42643, 42649, 42667, 42677, 42683, 42689, 42697, 42701, 42703, 42709, 42719,
42727, 42737, 42743, 42751, 42767, 42773, 42787, 42793, 42797, 42821, 42829,
42839, 42841, 42853, 42859, 42863, 42899, 42901, 42923, 42929, 42937, 42943,
42953, 42961, 42967, 42979, 42989, 43003, 43013, 43019, 43037, 43049, 43051,
43063, 43067, 43093, 43103, 43117, 43133, 43151, 43159, 43177, 43189, 43201,
43207, 43223, 43237, 43261, 43271, 43283, 43291, 43313, 43319, 43321, 43331,
43391, 43397, 43399, 43403, 43411, 43427, 43441, 43451, 43457, 43481, 43487,
43499, 43517, 43541, 43543, 43573, 43577, 43579, 43591, 43597, 43607, 43609,
43613, 43627, 43633, 43649, 43651, 43661, 43669, 43691, 43711, 43717, 43721,
43753, 43759, 43777, 43781, 43783, 43787, 43789, 43793, 43801, 43853, 43867,
43889, 43891, 43913, 43933, 43943, 43951, 43961, 43963, 43969, 43973, 43987,
43991, 43997, 44017, 44021, 44027, 44029, 44041, 44053, 44059, 44071, 44087,
44089, 44101, 44111, 44119, 44123, 44129, 44131, 44159, 44171, 44179, 44189,
44201, 44203, 44207, 44221, 44249, 44257, 44263, 44267, 44269, 44273, 44279,
44281, 44293, 44351, 44357, 44371, 44381, 44383, 44389, 44417, 44449, 44453,
44483, 44491, 44497, 44501, 44507, 44519, 44531, 44533, 44537, 44543, 44549,
44563, 44579, 44587, 44617, 44621, 44623, 44633, 44641, 44647, 44651, 44657,
44683, 44687, 44699, 44701, 44711, 44729, 44741, 44753, 44771, 44773, 44777,
44789, 44797, 44809, 44819, 44839, 44843, 44851, 44867, 44879, 44887, 44893,
44909, 44917, 44927, 44939, 44953, 44959, 44963, 44971, 44983, 44987, 45007,
45013, 45053, 45061, 45077, 45083, 45119, 45121, 45127, 45131, 45137, 45139,
45161, 45179, 45181, 45191, 45197, 45233, 45247, 45259, 45263, 45281, 45289,
45293, 45307, 45317, 45319, 45329, 45337, 45341, 45343, 45361, 45377, 45389,
45403, 45413, 45427, 45433, 45439, 45481, 45491, 45497, 45503, 45523, 45533,
45541, 45553, 45557, 45569, 45587, 45589, 45599, 45613, 45631, 45641, 45659,
45667, 45673, 45677, 45691, 45697, 45707, 45737, 45751, 45757, 45763, 45767,
45779, 45817, 45821, 45823, 45827, 45833, 45841, 45853, 45863, 45869, 45887,
45893, 45943, 45949, 45953, 45959, 45971, 45979, 45989, 46021, 46027, 46049,
46051, 46061, 46073, 46091, 46093, 46099, 46103, 46133, 46141, 46147, 46153,
46171, 46181, 46183, 46187, 46199, 46219, 46229, 46237, 46261, 46271, 46273,
46279, 46301, 46307, 46309, 46327, 46337, 46349, 46351, 46381, 46399, 46411,
46439, 46441, 46447, 46451, 46457, 46471, 46477, 46489, 46499, 46507, 46511,
46523, 46549, 46559, 46567, 46573, 46589, 46591, 46601, 46619, 46633, 46639,
46643, 46649, 46663, 46679, 46681, 46687, 46691, 46703, 46723, 46727, 46747,
46751, 46757, 46769, 46771, 46807, 46811, 46817, 46819, 46829, 46831, 46853,
46861, 46867, 46877, 46889, 46901, 46919, 46933, 46957, 46993, 46997, 47017,
47041, 47051, 47057, 47059, 47087, 47093, 47111, 47119, 47123, 47129, 47137,
47143, 47147, 47149, 47161, 47189, 47207, 47221, 47237, 47251, 47269, 47279,
47287, 47293, 47297, 47303, 47309, 47317, 47339, 47351, 47353, 47363, 47381,
47387, 47389, 47407, 47417, 47419, 47431, 47441, 47459, 47491, 47497, 47501,
47507, 47513, 47521, 47527, 47533, 47543, 47563, 47569, 47581, 47591, 47599,
47609, 47623, 47629, 47639, 47653, 47657, 47659, 47681, 47699, 47701, 47711,
47713, 47717, 47737, 47741, 47743, 47777, 47779, 47791, 47797, 47807, 47809,
47819, 47837, 47843, 47857, 47869, 47881, 47903, 47911, 47917, 47933, 47939,
47947, 47951, 47963, 47969, 47977, 47981, 48017, 48023, 48029, 48049, 48073,
48079, 48091, 48109, 48119, 48121, 48131, 48157, 48163, 48179, 48187, 48193,
48197, 48221, 48239, 48247, 48259, 48271, 48281, 48299, 48311, 48313, 48337,
48341, 48353, 48371, 48383, 48397, 48407, 48409, 48413, 48437, 48449, 48463,
48473, 48479, 48481, 48487, 48491, 48497, 48523, 48527, 48533, 48539, 48541,
48563, 48571, 48589, 48593, 48611, 48619, 48623, 48647, 48649, 48661, 48673,
48677, 48679, 48731, 48733, 48751, 48757, 48761, 48767, 48779, 48781, 48787,
48799, 48809, 48817, 48821, 48823, 48847, 48857, 48859, 48869, 48871, 48883,
48889, 48907, 48947, 48953, 48973, 48989, 48991, 49003, 49009, 49019, 49031,
49033, 49037, 49043, 49057, 49069, 49081, 49103, 49109, 49117, 49121, 49123,
49139, 49157, 49169, 49171, 49177, 49193, 49199, 49201, 49207, 49211, 49223,
49253, 49261, 49277, 49279, 49297, 49307, 49331, 49333, 49339, 49363, 49367,
49369, 49391, 49393, 49409, 49411, 49417, 49429, 49433, 49451, 49459, 49463,
49477, 49481, 49499, 49523, 49529, 49531, 49537, 49547, 49549, 49559, 49597,
49603, 49613, 49627, 49633, 49639, 49663, 49667, 49669, 49681, 49697, 49711,
49727, 49739, 49741, 49747, 49757, 49783, 49787, 49789, 49801, 49807, 49811,
49823, 49831, 49843, 49853, 49871, 49877, 49891, 49919, 49921, 49927, 49937,
49939, 49943, 49957, 49991, 49993, 49999, 50021, 50023, 50033, 50047, 50051,
50053, 50069, 50077, 50087, 50093, 50101, 50111, 50119, 50123, 50129, 50131,
50147, 50153, 50159, 50177, 50207, 50221, 50227, 50231, 50261, 50263, 50273,
50287, 50291, 50311, 50321, 50329, 50333, 50341, 50359, 50363, 50377, 50383,
50387, 50411, 50417, 50423, 50441, 50459, 50461, 50497, 50503, 50513, 50527,
50539, 50543, 50549, 50551, 50581, 50587, 50591, 50593, 50599, 50627, 50647,
50651, 50671, 50683, 50707, 50723, 50741, 50753, 50767, 50773, 50777, 50789,
50821, 50833, 50839, 50849, 50857, 50867, 50873, 50891, 50893, 50909, 50923,
50929, 50951, 50957, 50969, 50971, 50989, 50993, 51001, 51031, 51043, 51047,
51059, 51061, 51071, 51109, 51131, 51133, 51137, 51151, 51157, 51169, 51193,
51197, 51199, 51203, 51217, 51229, 51239, 51241, 51257, 51263, 51283, 51287,
51307, 51329, 51341, 51343, 51347, 51349, 51361, 51383, 51407, 51413, 51419,
51421, 51427, 51431, 51437, 51439, 51449, 51461, 51473, 51479, 51481, 51487,
51503, 51511, 51517, 51521, 51539, 51551, 51563, 51577, 51581, 51593, 51599,
51607, 51613, 51631, 51637, 51647, 51659, 51673, 51679, 51683, 51691, 51713,
51719, 51721, 51749, 51767, 51769, 51787, 51797, 51803, 51817, 51827, 51829,
51839, 51853, 51859, 51869, 51871, 51893, 51899, 51907, 51913, 51929, 51941,
51949, 51971, 51973, 51977, 51991, 52009, 52021, 52027, 52051, 52057, 52067,
52069, 52081, 52103, 52121, 52127, 52147, 52153, 52163, 52177, 52181, 52183,
52189, 52201, 52223, 52237, 52249, 52253, 52259, 52267, 52289, 52291, 52301,
52313, 52321, 52361, 52363, 52369, 52379, 52387, 52391, 52433, 52453, 52457,
52489, 52501, 52511, 52517, 52529, 52541, 52543, 52553, 52561, 52567, 52571,
52579, 52583, 52609, 52627, 52631, 52639, 52667, 52673, 52691, 52697, 52709,
52711, 52721, 52727, 52733, 52747, 52757, 52769, 52783, 52807, 52813, 52817,
52837, 52859, 52861, 52879, 52883, 52889, 52901, 52903, 52919, 52937, 52951,
52957, 52963, 52967, 52973, 52981, 52999, 53003, 53017, 53047, 53051, 53069,
53077, 53087, 53089, 53093, 53101, 53113, 53117, 53129, 53147, 53149, 53161,
53171, 53173, 53189, 53197, 53201, 53231, 53233, 53239, 53267, 53269, 53279,
53281, 53299, 53309, 53323, 53327, 53353, 53359, 53377, 53381, 53401, 53407,
53411, 53419, 53437, 53441, 53453, 53479, 53503, 53507, 53527, 53549, 53551,
53569, 53591, 53593, 53597, 53609, 53611, 53617, 53623, 53629, 53633, 53639,
53653, 53657, 53681, 53693, 53699, 53717, 53719, 53731, 53759, 53773, 53777,
53783, 53791, 53813, 53819, 53831, 53849, 53857, 53861, 53881, 53887, 53891,
53897, 53899, 53917, 53923, 53927, 53939, 53951, 53959, 53987, 53993, 54001,
54011, 54013, 54037, 54049, 54059, 54083, 54091, 54101, 54121, 54133, 54139,
54151, 54163, 54167, 54181, 54193, 54217, 54251, 54269, 54277, 54287, 54293,
54311, 54319, 54323, 54331, 54347, 54361, 54367, 54371, 54377, 54401, 54403,
54409, 54413, 54419, 54421, 54437, 54443, 54449, 54469, 54493, 54497, 54499,
54503, 54517, 54521, 54539, 54541, 54547, 54559, 54563, 54577, 54581, 54583,
54601, 54617, 54623, 54629, 54631, 54647, 54667, 54673, 54679, 54709, 54713,
54721, 54727, 54751, 54767, 54773, 54779, 54787, 54799, 54829, 54833, 54851,
54869, 54877, 54881, 54907, 54917, 54919, 54941, 54949, 54959, 54973, 54979,
54983, 55001, 55009, 55021, 55049, 55051, 55057, 55061, 55073, 55079, 55103,
55109, 55117, 55127, 55147, 55163, 55171, 55201, 55207, 55213, 55217, 55219,
55229, 55243, 55249, 55259, 55291, 55313, 55331, 55333, 55337, 55339, 55343,
55351, 55373, 55381, 55399, 55411, 55439, 55441, 55457, 55469, 55487, 55501,
55511, 55529, 55541, 55547, 55579, 55589, 55603, 55609, 55619, 55621, 55631,
55633, 55639, 55661, 55663, 55667, 55673, 55681, 55691, 55697, 55711, 55717,
55721, 55733, 55763, 55787, 55793, 55799, 55807, 55813, 55817, 55819, 55823,
55829, 55837, 55843, 55849, 55871, 55889, 55897, 55901, 55903, 55921, 55927,
55931, 55933, 55949, 55967, 55987, 55997, 56003, 56009, 56039, 56041, 56053,
56081, 56087, 56093, 56099, 56101, 56113, 56123, 56131, 56149, 56167, 56171,
56179, 56197, 56207, 56209, 56237, 56239, 56249, 56263, 56267, 56269, 56299,
56311, 56333, 56359, 56369, 56377, 56383, 56393, 56401, 56417, 56431, 56437,
56443, 56453, 56467, 56473, 56477, 56479, 56489, 56501, 56503, 56509, 56519,
56527, 56531, 56533, 56543, 56569, 56591, 56597, 56599, 56611, 56629, 56633,
56659, 56663, 56671, 56681, 56687, 56701, 56711, 56713, 56731, 56737, 56747,
56767, 56773, 56779, 56783, 56807, 56809, 56813, 56821, 56827, 56843, 56857,
56873, 56891, 56893, 56897, 56909, 56911, 56921, 56923, 56929, 56941, 56951,
56957, 56963, 56983, 56989, 56993, 56999, 57037, 57041, 57047, 57059, 57073,
57077, 57089, 57097, 57107, 57119, 57131, 57139, 57143, 57149, 57163, 57173,
57179, 57191, 57193, 57203, 57221, 57223, 57241, 57251, 57259, 57269, 57271,
57283, 57287, 57301, 57329, 57331, 57347, 57349, 57367, 57373, 57383, 57389,
57397, 57413, 57427, 57457, 57467, 57487, 57493, 57503, 57527, 57529, 57557,
57559, 57571, 57587, 57593, 57601, 57637, 57641, 57649, 57653, 57667, 57679,
57689, 57697, 57709, 57713, 57719, 57727, 57731, 57737, 57751, 57773, 57781,
57787, 57791, 57793, 57803, 57809, 57829, 57839, 57847, 57853, 57859, 57881,
57899, 57901, 57917, 57923, 57943, 57947, 57973, 57977, 57991, 58013, 58027,
58031, 58043, 58049, 58057, 58061, 58067, 58073, 58099, 58109, 58111, 58129,
58147, 58151, 58153, 58169, 58171, 58189, 58193, 58199, 58207, 58211, 58217,
58229, 58231, 58237, 58243, 58271, 58309, 58313, 58321, 58337, 58363, 58367,
58369, 58379, 58391, 58393, 58403, 58411, 58417, 58427, 58439, 58441, 58451,
58453, 58477, 58481, 58511, 58537, 58543, 58549, 58567, 58573, 58579, 58601,
58603, 58613, 58631, 58657, 58661, 58679, 58687, 58693, 58699, 58711, 58727,
58733, 58741, 58757, 58763, 58771, 58787, 58789, 58831, 58889, 58897, 58901,
58907, 58909, 58913, 58921, 58937, 58943, 58963, 58967, 58979, 58991, 58997,
59009, 59011, 59021, 59023, 59029, 59051, 59053, 59063, 59069, 59077, 59083,
59093, 59107, 59113, 59119, 59123, 59141, 59149, 59159, 59167, 59183, 59197,
59207, 59209, 59219, 59221, 59233, 59239, 59243, 59263, 59273, 59281, 59333,
59341, 59351, 59357, 59359, 59369, 59377, 59387, 59393, 59399, 59407, 59417,
59419, 59441, 59443, 59447, 59453, 59467, 59471, 59473, 59497, 59509, 59513,
59539, 59557, 59561, 59567, 59581, 59611, 59617, 59621, 59627, 59629, 59651,
59659, 59663, 59669, 59671, 59693, 59699, 59707, 59723, 59729, 59743, 59747,
59753, 59771, 59779, 59791, 59797, 59809, 59833, 59863, 59879, 59887, 59921,
59929, 59951, 59957, 59971, 59981, 59999, 60013, 60017, 60029, 60037, 60041,
60077, 60083, 60089, 60091, 60101, 60103, 60107, 60127, 60133, 60139, 60149,
60161, 60167, 60169, 60209, 60217, 60223, 60251, 60257, 60259, 60271, 60289,
60293, 60317, 60331, 60337, 60343, 60353, 60373, 60383, 60397, 60413, 60427,
60443, 60449, 60457, 60493, 60497, 60509, 60521, 60527, 60539, 60589, 60601,
60607, 60611, 60617, 60623, 60631, 60637, 60647, 60649, 60659, 60661, 60679,
60689, 60703, 60719, 60727, 60733, 60737, 60757, 60761, 60763, 60773, 60779,
60793, 60811, 60821, 60859, 60869, 60887, 60889, 60899, 60901, 60913, 60917,
60919, 60923, 60937, 60943, 60953, 60961, 61001, 61007, 61027, 61031, 61043,
61051, 61057, 61091, 61099, 61121, 61129, 61141, 61151, 61153, 61169, 61211,
61223, 61231, 61253, 61261, 61283, 61291, 61297, 61331, 61333, 61339, 61343,
61357, 61363, 61379, 61381, 61403, 61409, 61417, 61441, 61463, 61469, 61471,
61483, 61487, 61493, 61507, 61511, 61519, 61543, 61547, 61553, 61559, 61561,
61583, 61603, 61609, 61613, 61627, 61631, 61637, 61643, 61651, 61657, 61667,
61673, 61681, 61687, 61703, 61717, 61723, 61729, 61751, 61757, 61781, 61813,
61819, 61837, 61843, 61861, 61871, 61879, 61909, 61927, 61933, 61949, 61961,
61967, 61979, 61981, 61987, 61991, 62003, 62011, 62017, 62039, 62047, 62053,
62057, 62071, 62081, 62099, 62119, 62129, 62131, 62137, 62141, 62143, 62171,
62189, 62191, 62201, 62207, 62213, 62219, 62233, 62273, 62297, 62299, 62303,
62311, 62323, 62327, 62347, 62351, 62383, 62401, 62417, 62423, 62459, 62467,
62473, 62477, 62483, 62497, 62501, 62507, 62533, 62539, 62549, 62563, 62581,
62591, 62597, 62603, 62617, 62627, 62633, 62639, 62653, 62659, 62683, 62687,
62701, 62723, 62731, 62743, 62753, 62761, 62773, 62791, 62801, 62819, 62827,
62851, 62861, 62869, 62873, 62897, 62903, 62921, 62927, 62929, 62939, 62969,
62971, 62981, 62983, 62987, 62989, 63029, 63031, 63059, 63067, 63073, 63079,
63097, 63103, 63113, 63127, 63131, 63149, 63179, 63197, 63199, 63211, 63241,
63247, 63277, 63281, 63299, 63311, 63313, 63317, 63331, 63337, 63347, 63353,
63361, 63367, 63377, 63389, 63391, 63397, 63409, 63419, 63421, 63439, 63443,
63463, 63467, 63473, 63487, 63493, 63499, 63521, 63527, 63533, 63541, 63559,
63577, 63587, 63589, 63599, 63601, 63607, 63611, 63617, 63629, 63647, 63649,
63659, 63667, 63671, 63689, 63691, 63697, 63703, 63709, 63719, 63727, 63737,
63743, 63761, 63773, 63781, 63793, 63799, 63803, 63809, 63823, 63839, 63841,
63853, 63857, 63863, 63901, 63907, 63913, 63929, 63949, 63977, 63997, 64007,
64013, 64019, 64033, 64037, 64063, 64067, 64081, 64091, 64109, 64123, 64151,
64153, 64157, 64171, 64187, 64189, 64217, 64223, 64231, 64237, 64271, 64279,
64283, 64301, 64303, 64319, 64327, 64333, 64373, 64381, 64399, 64403, 64433,
64439, 64451, 64453, 64483, 64489, 64499, 64513, 64553, 64567, 64577, 64579,
64591, 64601, 64609, 64613, 64621, 64627, 64633, 64661, 64663, 64667, 64679,
64693, 64709, 64717, 64747, 64763, 64781, 64783, 64793, 64811, 64817, 64849,
64853, 64871, 64877, 64879, 64891, 64901, 64919, 64921, 64927, 64937, 64951,
64969, 64997, 65003, 65011, 65027, 65029, 65033, 65053, 65063, 65071, 65089,
65099, 65101, 65111, 65119, 65123, 65129, 65141, 65147, 65167, 65171, 65173,
65179, 65183, 65203, 65213, 65239, 65257, 65267, 65269, 65287, 65293, 65309,
65323, 65327, 65353, 65357, 65371, 65381, 65393, 65407, 65413, 65419, 65423,
65437, 65447, 65449, 65479, 65497, 65519, 65521, 0 };

}
/*
* Modular Reducer
* (C) 1999-2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Modular_Reducer Constructor
*/
Modular_Reducer::Modular_Reducer(const BigInt& mod)
   {
   if(mod <= 0)
      throw Invalid_Argument("Modular_Reducer: modulus must be positive");

   m_modulus = mod;
   m_mod_words = m_modulus.sig_words();

   m_modulus_2 = Botan::square(m_modulus);

   m_mu = BigInt::power_of_2(2 * MP_WORD_BITS * m_mod_words) / m_modulus;
   }

/*
* Barrett Reduction
*/
BigInt Modular_Reducer::reduce(const BigInt& x) const
   {
   if(m_mod_words == 0)
      throw Invalid_State("Modular_Reducer: Never initalized");

   if(x.cmp(m_modulus, false) < 0)
      {
      if(x.is_negative())
         return x + m_modulus; // make positive
      return x;
      }
   else if(x.cmp(m_modulus_2, false) < 0)
      {
      BigInt t1 = x;
      t1.set_sign(BigInt::Positive);
      t1 >>= (MP_WORD_BITS * (m_mod_words - 1));
      t1 *= m_mu;

      t1 >>= (MP_WORD_BITS * (m_mod_words + 1));
      t1 *= m_modulus;

      t1.mask_bits(MP_WORD_BITS * (m_mod_words + 1));

      BigInt t2 = x;
      t2.set_sign(BigInt::Positive);
      t2.mask_bits(MP_WORD_BITS * (m_mod_words + 1));

      t2 -= t1;

      if(t2.is_negative())
         {
         t2 += BigInt::power_of_2(MP_WORD_BITS * (m_mod_words + 1));
         }

      while(t2 >= m_modulus)
         t2 -= m_modulus;

      if(x.is_positive())
         return t2;
      else
         return (m_modulus - t2);
      }
   else
      {
      // too big, fall back to normal division
      return (x % m_modulus);
      }
   }

}
/*
* Shanks-Tonnelli (RESSOL)
* (C) 2007-2008 Falko Strenzke, FlexSecure GmbH
* (C) 2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Shanks-Tonnelli algorithm
*/
BigInt ressol(const BigInt& a, const BigInt& p)
   {
   if(a == 0)
      return 0;
   else if(a < 0)
      throw Invalid_Argument("ressol: value to solve for must be positive");
   else if(a >= p)
      throw Invalid_Argument("ressol: value to solve for must be less than p");

   if(p == 2)
      return a;
   else if(p <= 1)
      throw Invalid_Argument("ressol: prime must be > 1 a");
   else if(p.is_even())
      throw Invalid_Argument("ressol: invalid prime");

   if(jacobi(a, p) != 1) // not a quadratic residue
      return -BigInt(1);

   if(p % 4 == 3)
      return power_mod(a, ((p+1) >> 2), p);

   size_t s = low_zero_bits(p - 1);
   BigInt q = p >> s;

   q -= 1;
   q >>= 1;

   Modular_Reducer mod_p(p);

   BigInt r = power_mod(a, q, p);
   BigInt n = mod_p.multiply(a, mod_p.square(r));
   r = mod_p.multiply(r, a);

   if(n == 1)
      return r;

   // find random non quadratic residue z
   BigInt z = 2;
   while(jacobi(z, p) == 1) // while z quadratic residue
      ++z;

   BigInt c = power_mod(z, (q << 1) + 1, p);

   while(n > 1)
      {
      q = n;

      size_t i = 0;
      while(q != 1)
         {
         q = mod_p.square(q);
         ++i;

         if(i >= s)
            {
            return -BigInt(1);
            }
         }

      c = power_mod(c, BigInt::power_of_2(s-i-1), p);
      r = mod_p.multiply(r, c);
      c = mod_p.square(c);
      n = mod_p.multiply(n, c);
      s = i;
      }

   return r;
   }

}
/*
* PKCS #5 PBES2
* (C) 1999-2008,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

/*
* Encode PKCS#5 PBES2 parameters
*/
std::vector<uint8_t> encode_pbes2_params(const std::string& cipher,
                                      const std::string& prf,
                                      const secure_vector<uint8_t>& salt,
                                      const secure_vector<uint8_t>& iv,
                                      size_t iterations,
                                      size_t key_length)
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
      .encode(
         AlgorithmIdentifier("PKCS5.PBKDF2",
            DER_Encoder()
               .start_cons(SEQUENCE)
                  .encode(salt, OCTET_STRING)
                  .encode(iterations)
                  .encode(key_length)
                  .encode_if(
                     prf != "HMAC(SHA-160)",
                     AlgorithmIdentifier(prf, AlgorithmIdentifier::USE_NULL_PARAM))
               .end_cons()
            .get_contents_unlocked()
            )
         )
      .encode(
         AlgorithmIdentifier(cipher,
            DER_Encoder().encode(iv, OCTET_STRING).get_contents_unlocked()
            )
         )
      .end_cons()
      .get_contents_unlocked();
   }

/*
* PKCS#5 v2.0 PBE Encryption
*/
std::pair<AlgorithmIdentifier, std::vector<uint8_t>>
pbes2_encrypt_shared(const secure_vector<uint8_t>& key_bits,
                     const std::string& passphrase,
                     size_t* msec_in_iterations_out,
                     size_t iterations_if_msec_null,
                     const std::string& cipher,
                     const std::string& digest,
                     RandomNumberGenerator& rng)
   {
   const std::string prf = "HMAC(" + digest + ")";

   const std::vector<std::string> cipher_spec = split_on(cipher, '/');
   if(cipher_spec.size() != 2)
      throw Decoding_Error("PBE-PKCS5 v2.0: Invalid cipher spec " + cipher);

   const secure_vector<uint8_t> salt = rng.random_vec(12);

   if(cipher_spec[1] != "CBC" && cipher_spec[1] != "GCM")
      throw Decoding_Error("PBE-PKCS5 v2.0: Don't know param format for " + cipher);

   std::unique_ptr<Cipher_Mode> enc(get_cipher_mode(cipher, ENCRYPTION));

   if(!enc)
      throw Decoding_Error("PBE-PKCS5 cannot encrypt no cipher " + cipher);

   std::unique_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(" + prf + ")"));

   const size_t key_length = enc->key_spec().maximum_keylength();


   secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

   size_t iterations = iterations_if_msec_null;

   if(msec_in_iterations_out)
      {
      std::chrono::milliseconds msec(*msec_in_iterations_out);
      enc->set_key(pbkdf->derive_key(key_length, passphrase, salt.data(), salt.size(), msec, iterations).bits_of());
      *msec_in_iterations_out = iterations;
      }
   else
      {
      enc->set_key(pbkdf->pbkdf_iterations(key_length, passphrase, salt.data(), salt.size(), iterations));
      }

   enc->start(iv);
   secure_vector<uint8_t> buf = key_bits;
   enc->finish(buf);

   AlgorithmIdentifier id(
      OIDS::lookup("PBE-PKCS5v20"),
      encode_pbes2_params(cipher, prf, salt, iv, iterations, key_length));

   return std::make_pair(id, unlock(buf));
   }


}

std::pair<AlgorithmIdentifier, std::vector<uint8_t>>
pbes2_encrypt(const secure_vector<uint8_t>& key_bits,
              const std::string& passphrase,
              std::chrono::milliseconds msec,
              const std::string& cipher,
              const std::string& digest,
              RandomNumberGenerator& rng)
   {
   size_t msec_in_iterations_out = static_cast<size_t>(msec.count());
   return pbes2_encrypt_shared(key_bits, passphrase, &msec_in_iterations_out, 0, cipher, digest, rng);
   // return value msec_in_iterations_out discarded
   }

std::pair<AlgorithmIdentifier, std::vector<uint8_t>>
pbes2_encrypt_msec(const secure_vector<uint8_t>& key_bits,
                   const std::string& passphrase,
                   std::chrono::milliseconds msec,
                   size_t* out_iterations_if_nonnull,
                   const std::string& cipher,
                   const std::string& digest,
                   RandomNumberGenerator& rng)
   {
   size_t msec_in_iterations_out = static_cast<size_t>(msec.count());

   auto ret = pbes2_encrypt_shared(key_bits, passphrase, &msec_in_iterations_out, 0, cipher, digest, rng);

   if(out_iterations_if_nonnull)
      *out_iterations_if_nonnull = msec_in_iterations_out;

   return ret;
   }

std::pair<AlgorithmIdentifier, std::vector<uint8_t>>
pbes2_encrypt_iter(const secure_vector<uint8_t>& key_bits,
                   const std::string& passphrase,
                   size_t pbkdf_iter,
                   const std::string& cipher,
                   const std::string& digest,
                   RandomNumberGenerator& rng)
   {
   return pbes2_encrypt_shared(key_bits, passphrase, nullptr, pbkdf_iter, cipher, digest, rng);
   }

secure_vector<uint8_t>
pbes2_decrypt(const secure_vector<uint8_t>& key_bits,
              const std::string& passphrase,
              const std::vector<uint8_t>& params)
   {
   AlgorithmIdentifier kdf_algo, enc_algo;

   BER_Decoder(params)
      .start_cons(SEQUENCE)
         .decode(kdf_algo)
         .decode(enc_algo)
      .end_cons();

   AlgorithmIdentifier prf_algo;

   if(kdf_algo.oid != OIDS::lookup("PKCS5.PBKDF2"))
      throw Decoding_Error("PBE-PKCS5 v2.0: Unknown KDF algorithm " +
                           kdf_algo.oid.as_string());

   secure_vector<uint8_t> salt;
   size_t iterations = 0, key_length = 0;

   BER_Decoder(kdf_algo.parameters)
      .start_cons(SEQUENCE)
         .decode(salt, OCTET_STRING)
         .decode(iterations)
         .decode_optional(key_length, INTEGER, UNIVERSAL)
         .decode_optional(prf_algo, SEQUENCE, CONSTRUCTED,
                          AlgorithmIdentifier("HMAC(SHA-160)",
                                              AlgorithmIdentifier::USE_NULL_PARAM))
      .end_cons();

   const std::string cipher = OIDS::lookup(enc_algo.oid);
   const std::vector<std::string> cipher_spec = split_on(cipher, '/');
   if(cipher_spec.size() != 2)
      throw Decoding_Error("PBE-PKCS5 v2.0: Invalid cipher spec " + cipher);
   if(cipher_spec[1] != "CBC" && cipher_spec[1] != "GCM")
      throw Decoding_Error("PBE-PKCS5 v2.0: Don't know param format for " + cipher);

   if(salt.size() < 8)
      throw Decoding_Error("PBE-PKCS5 v2.0: Encoded salt is too small");

   secure_vector<uint8_t> iv;
   BER_Decoder(enc_algo.parameters).decode(iv, OCTET_STRING).verify_end();

   const std::string prf = OIDS::lookup(prf_algo.oid);

   std::unique_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(" + prf + ")"));

   std::unique_ptr<Cipher_Mode> dec(get_cipher_mode(cipher, DECRYPTION));
   if(!dec)
      throw Decoding_Error("PBE-PKCS5 cannot decrypt no cipher " + cipher);

   if(key_length == 0)
      key_length = dec->key_spec().maximum_keylength();

   dec->set_key(pbkdf->pbkdf_iterations(key_length, passphrase, salt.data(), salt.size(), iterations));

   dec->start(iv);

   secure_vector<uint8_t> buf = key_bits;
   dec->finish(buf);

   return buf;
   }

}
/*
* PBKDF
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_PBKDF1)
#endif

#if defined(BOTAN_HAS_PBKDF2)
#endif

#if defined(BOTAN_HAS_PGP_S2K)
#endif

namespace Botan {

std::unique_ptr<PBKDF> PBKDF::create(const std::string& algo_spec,
                                     const std::string& provider)
   {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_PBKDF2)
   if(req.algo_name() == "PBKDF2")
      {
      // TODO OpenSSL

      if(provider.empty() || provider == "base")
         {
         if(auto mac = MessageAuthenticationCode::create(req.arg(0)))
            return std::unique_ptr<PBKDF>(new PKCS5_PBKDF2(mac.release()));

         if(auto mac = MessageAuthenticationCode::create("HMAC(" + req.arg(0) + ")"))
            return std::unique_ptr<PBKDF>(new PKCS5_PBKDF2(mac.release()));
         }

      return nullptr;
      }
#endif

#if defined(BOTAN_HAS_PBKDF1)
   if(req.algo_name() == "PBKDF1" && req.arg_count() == 1)
      {
      if(auto hash = HashFunction::create(req.arg(0)))
         return std::unique_ptr<PBKDF>(new PKCS5_PBKDF1(hash.release()));

      }
#endif

#if defined(BOTAN_HAS_PGP_S2K)
   if(req.algo_name() == "OpenPGP-S2K" && req.arg_count() == 1)
      {
      if(auto hash = HashFunction::create(req.arg(0)))
         return std::unique_ptr<PBKDF>(new OpenPGP_S2K(hash.release()));
      }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
   }

//static
std::unique_ptr<PBKDF>
PBKDF::create_or_throw(const std::string& algo,
                             const std::string& provider)
   {
   if(auto pbkdf = PBKDF::create(algo, provider))
      {
      return pbkdf;
      }
   throw Lookup_Error("PBKDF", algo, provider);
   }

std::vector<std::string> PBKDF::providers(const std::string& algo_spec)
   {
   return probe_providers_of<PBKDF>(algo_spec, { "base", "openssl" });
   }

void PBKDF::pbkdf_timed(uint8_t out[], size_t out_len,
                        const std::string& passphrase,
                        const uint8_t salt[], size_t salt_len,
                        std::chrono::milliseconds msec,
                        size_t& iterations) const
   {
   iterations = pbkdf(out, out_len, passphrase, salt, salt_len, 0, msec);
   }

void PBKDF::pbkdf_iterations(uint8_t out[], size_t out_len,
                             const std::string& passphrase,
                             const uint8_t salt[], size_t salt_len,
                             size_t iterations) const
   {
   if(iterations == 0)
      throw Invalid_Argument(name() + ": Invalid iteration count");

   const size_t iterations_run = pbkdf(out, out_len, passphrase,
                                       salt, salt_len, iterations,
                                       std::chrono::milliseconds(0));
   BOTAN_ASSERT_EQUAL(iterations, iterations_run, "Expected PBKDF iterations");
   }

secure_vector<uint8_t> PBKDF::pbkdf_iterations(size_t out_len,
                                            const std::string& passphrase,
                                            const uint8_t salt[], size_t salt_len,
                                            size_t iterations) const
   {
   secure_vector<uint8_t> out(out_len);
   pbkdf_iterations(out.data(), out_len, passphrase, salt, salt_len, iterations);
   return out;
   }

secure_vector<uint8_t> PBKDF::pbkdf_timed(size_t out_len,
                                       const std::string& passphrase,
                                       const uint8_t salt[], size_t salt_len,
                                       std::chrono::milliseconds msec,
                                       size_t& iterations) const
   {
   secure_vector<uint8_t> out(out_len);
   pbkdf_timed(out.data(), out_len, passphrase, salt, salt_len, msec, iterations);
   return out;
   }

}
/*
* PBKDF2
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

size_t
pbkdf2(MessageAuthenticationCode& prf,
       uint8_t out[],
       size_t out_len,
       const std::string& passphrase,
       const uint8_t salt[], size_t salt_len,
       size_t iterations,
       std::chrono::milliseconds msec)
   {
   clear_mem(out, out_len);

   if(out_len == 0)
      return 0;

   try
      {
      prf.set_key(cast_char_ptr_to_uint8(passphrase.data()), passphrase.size());
      }
   catch(Invalid_Key_Length&)
      {
      throw Exception("PBKDF2 with " + prf.name() +
                               " cannot accept passphrases of length " +
                               std::to_string(passphrase.size()));
      }

   const size_t prf_sz = prf.output_length();
   secure_vector<uint8_t> U(prf_sz);

   const size_t blocks_needed = round_up(out_len, prf_sz) / prf_sz;

   std::chrono::microseconds usec_per_block =
      std::chrono::duration_cast<std::chrono::microseconds>(msec) / blocks_needed;

   uint32_t counter = 1;
   while(out_len)
      {
      const size_t prf_output = std::min<size_t>(prf_sz, out_len);

      prf.update(salt, salt_len);
      prf.update_be(counter++);
      prf.final(U.data());

      xor_buf(out, U.data(), prf_output);

      if(iterations == 0)
         {
         /*
         If no iterations set, run the first block to calibrate based
         on how long hashing takes on whatever machine we're running on.
         */

         const auto start = std::chrono::high_resolution_clock::now();

         iterations = 1; // the first iteration we did above

         while(true)
            {
            prf.update(U);
            prf.final(U.data());
            xor_buf(out, U.data(), prf_output);
            iterations++;

            /*
            Only break on relatively 'even' iterations. For one it
            avoids confusion, and likely some broken implementations
            break on getting completely randomly distributed values
            */
            if(iterations % 10000 == 0)
               {
               auto time_taken = std::chrono::high_resolution_clock::now() - start;
               auto usec_taken = std::chrono::duration_cast<std::chrono::microseconds>(time_taken);
               if(usec_taken > usec_per_block)
                  break;
               }
            }
         }
      else
         {
         for(size_t i = 1; i != iterations; ++i)
            {
            prf.update(U);
            prf.final(U.data());
            xor_buf(out, U.data(), prf_output);
            }
         }

      out_len -= prf_output;
      out += prf_output;
      }

   return iterations;
   }

size_t
PKCS5_PBKDF2::pbkdf(uint8_t key[], size_t key_len,
                    const std::string& passphrase,
                    const uint8_t salt[], size_t salt_len,
                    size_t iterations,
                    std::chrono::milliseconds msec) const
   {
   return pbkdf2(*m_mac.get(), key, key_len, passphrase, salt, salt_len, iterations, msec);
   }


}
/*
* PEM Encoding/Decoding
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace PEM_Code {

namespace {

std::string linewrap(size_t width, const std::string& in)
   {
   std::string out;
   for(size_t i = 0; i != in.size(); ++i)
      {
      if(i > 0 && i % width == 0)
         {
         out.push_back('\n');
         }
      out.push_back(in[i]);
      }
   if(out.size() > 0 && out[out.size()-1] != '\n')
      {
      out.push_back('\n');
      }

   return out;
   }

}

/*
* PEM encode BER/DER-encoded objects
*/
std::string encode(const uint8_t der[], size_t length, const std::string& label, size_t width)
   {
   const std::string PEM_HEADER = "-----BEGIN " + label + "-----\n";
   const std::string PEM_TRAILER = "-----END " + label + "-----\n";

   return (PEM_HEADER + linewrap(width, base64_encode(der, length)) + PEM_TRAILER);
   }

/*
* Decode PEM down to raw BER/DER
*/
secure_vector<uint8_t> decode_check_label(DataSource& source,
                                      const std::string& label_want)
   {
   std::string label_got;
   secure_vector<uint8_t> ber = decode(source, label_got);
   if(label_got != label_want)
      throw Decoding_Error("PEM: Label mismatch, wanted " + label_want +
                           ", got " + label_got);
   return ber;
   }

/*
* Decode PEM down to raw BER/DER
*/
secure_vector<uint8_t> decode(DataSource& source, std::string& label)
   {
   const size_t RANDOM_CHAR_LIMIT = 8;

   const std::string PEM_HEADER1 = "-----BEGIN ";
   const std::string PEM_HEADER2 = "-----";
   size_t position = 0;

   while(position != PEM_HEADER1.length())
      {
      uint8_t b;
      if(!source.read_byte(b))
         throw Decoding_Error("PEM: No PEM header found");
      if(b == PEM_HEADER1[position])
         ++position;
      else if(position >= RANDOM_CHAR_LIMIT)
         throw Decoding_Error("PEM: Malformed PEM header");
      else
         position = 0;
      }
   position = 0;
   while(position != PEM_HEADER2.length())
      {
      uint8_t b;
      if(!source.read_byte(b))
         throw Decoding_Error("PEM: No PEM header found");
      if(b == PEM_HEADER2[position])
         ++position;
      else if(position)
         throw Decoding_Error("PEM: Malformed PEM header");

      if(position == 0)
         label += static_cast<char>(b);
      }

   std::vector<char> b64;

   const std::string PEM_TRAILER = "-----END " + label + "-----";
   position = 0;
   while(position != PEM_TRAILER.length())
      {
      uint8_t b;
      if(!source.read_byte(b))
         throw Decoding_Error("PEM: No PEM trailer found");
      if(b == PEM_TRAILER[position])
         ++position;
      else if(position)
         throw Decoding_Error("PEM: Malformed PEM trailer");

      if(position == 0)
         b64.push_back(b);
      }

   return base64_decode(b64.data(), b64.size());
   }

secure_vector<uint8_t> decode_check_label(const std::string& pem,
                                      const std::string& label_want)
   {
   DataSource_Memory src(pem);
   return decode_check_label(src, label_want);
   }

secure_vector<uint8_t> decode(const std::string& pem, std::string& label)
   {
   DataSource_Memory src(pem);
   return decode(src, label);
   }

/*
* Search for a PEM signature
*/
bool matches(DataSource& source, const std::string& extra,
             size_t search_range)
   {
   const std::string PEM_HEADER = "-----BEGIN " + extra;

   secure_vector<uint8_t> search_buf(search_range);
   size_t got = source.peek(search_buf.data(), search_buf.size(), 0);

   if(got < PEM_HEADER.length())
      return false;

   size_t index = 0;

   for(size_t j = 0; j != got; ++j)
      {
      if(search_buf[j] == PEM_HEADER[index])
         ++index;
      else
         index = 0;
      if(index == PEM_HEADER.size())
         return true;
      }
   return false;
   }

}

}
/*
* EME Base Class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_EME_OAEP)
#endif

#if defined(BOTAN_HAS_EME_PKCS1v15)
#endif

#if defined(BOTAN_HAS_EME_RAW)
#endif

namespace Botan {

EME* get_eme(const std::string& algo_spec)
   {
#if defined(BOTAN_HAS_EME_RAW)
   if(algo_spec == "Raw")
      return new EME_Raw;
#endif

#if defined(BOTAN_HAS_EME_PKCS1v15)
   if(algo_spec == "PKCS1v15" || algo_spec == "EME-PKCS1-v1_5")
      return new EME_PKCS1v15;
#endif

#if defined(BOTAN_HAS_EME_OAEP)
   SCAN_Name req(algo_spec);

   if(req.algo_name() == "OAEP" ||
      req.algo_name() == "EME-OAEP" ||
      req.algo_name() == "EME1")
      {
      if(req.arg_count() == 1 ||
         (req.arg_count() == 2 && req.arg(1) == "MGF1"))
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            return new OAEP(hash.release());
         }
      }
#endif

   throw Algorithm_Not_Found(algo_spec);
   }

/*
* Encode a message
*/
secure_vector<uint8_t> EME::encode(const uint8_t msg[], size_t msg_len,
                                size_t key_bits,
                                RandomNumberGenerator& rng) const
   {
   return pad(msg, msg_len, key_bits, rng);
   }

/*
* Encode a message
*/
secure_vector<uint8_t> EME::encode(const secure_vector<uint8_t>& msg,
                                size_t key_bits,
                                RandomNumberGenerator& rng) const
   {
   return pad(msg.data(), msg.size(), key_bits, rng);
   }


}
/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_EMSA1)
#endif

#if defined(BOTAN_HAS_EMSA_X931)
#endif

#if defined(BOTAN_HAS_EMSA_PKCS1)
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
#endif

#if defined(BOTAN_HAS_EMSA_RAW)
#endif

#if defined(BOTAN_HAS_ISO_9796)
#endif

namespace Botan {

EMSA* get_emsa(const std::string& algo_spec)
   {
   SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_EMSA1)
   if(req.algo_name() == "EMSA1" && req.arg_count() == 1)
      {
      if(auto hash = HashFunction::create(req.arg(0)))
         return new EMSA1(hash.release());
      }
#endif

#if defined(BOTAN_HAS_EMSA_PKCS1)
   if(req.algo_name() == "EMSA_PKCS1" ||
         req.algo_name() == "EMSA-PKCS1-v1_5" ||
         req.algo_name() == "EMSA3")
      {
      if(req.arg_count() == 2 && req.arg(0) == "Raw")
         {
         return new EMSA_PKCS1v15_Raw(req.arg(1));
         }
      else if(req.arg_count() == 1)
         {
         if(req.arg(0) == "Raw")
            {
            return new EMSA_PKCS1v15_Raw;
            }
         else
            {
            if(auto hash = HashFunction::create(req.arg(0)))
               {
               return new EMSA_PKCS1v15(hash.release());
               }
            }
         }
      }
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
   if(req.algo_name() == "PSSR" ||
      req.algo_name() == "EMSA-PSS" ||
      req.algo_name() == "PSS-MGF1" ||
      req.algo_name() == "EMSA4" ||
      req.algo_name() == "PSSR_Raw")
      {
      if(req.arg_count_between(1, 3))
         {
         if(req.arg(1, "MGF1") != "MGF1")
            return nullptr; // not supported

         if(auto h = HashFunction::create(req.arg(0)))
            {
            const size_t salt_size = req.arg_as_integer(2, h->output_length());

            if(req.algo_name() == "PSSR_Raw")
               return new PSSR_Raw(h.release(), salt_size);
            else
               return new PSSR(h.release(), salt_size);
            }
         }
      }
#endif

#if defined(BOTAN_HAS_ISO_9796)
   if(req.algo_name() == "ISO_9796_DS2")
      {
      if(req.arg_count_between(1, 3))
         {
         if(auto h = HashFunction::create(req.arg(0)))
            {
            const size_t salt_size = req.arg_as_integer(2, h->output_length());
            const bool implicit = req.arg(1, "exp") == "imp";
            return new ISO_9796_DS2(h.release(), implicit, salt_size);
            }
         }
      }
   //ISO-9796-2 DS 3 is deterministic and DS2 without a salt
   if(req.algo_name() == "ISO_9796_DS3")
      {
      if(req.arg_count_between(1, 2))
         {
         if(auto h = HashFunction::create(req.arg(0)))
            {
            const bool implicit = req.arg(1, "exp") == "imp";
            return new ISO_9796_DS3(h.release(), implicit);
            }
         }
      }
#endif

#if defined(BOTAN_HAS_EMSA_X931)
   if(req.algo_name() == "EMSA_X931" ||
         req.algo_name() == "EMSA2" ||
         req.algo_name() == "X9.31")
      {
      if(req.arg_count() == 1)
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            {
            return new EMSA_X931(hash.release());
            }
         }
      }
#endif

#if defined(BOTAN_HAS_EMSA_RAW)
   if(req.algo_name() == "Raw")
      {
      if(req.arg_count() == 0)
         {
         return new EMSA_Raw;
         }
      else
         {
         auto hash = HashFunction::create(req.arg(0));
         if(hash)
            return new EMSA_Raw(hash->output_length());
         }
      }
#endif

   throw Algorithm_Not_Found(algo_spec);
   }

std::string hash_for_emsa(const std::string& algo_spec)
   {
   SCAN_Name emsa_name(algo_spec);

   if(emsa_name.arg_count() > 0)
      {
      const std::string pos_hash = emsa_name.arg(0);
      return pos_hash;
      }

   return "SHA-512"; // safe default if nothing we understand
   }

}


/*
* Blinding for public key operations
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

Blinder::Blinder(const BigInt& modulus,
                 RandomNumberGenerator& rng,
                 std::function<BigInt (const BigInt&)> fwd,
                 std::function<BigInt (const BigInt&)> inv) :
      m_reducer(modulus),
      m_rng(rng),
      m_fwd_fn(fwd),
      m_inv_fn(inv),
      m_modulus_bits(modulus.bits()),
      m_e{},
      m_d{},
      m_counter{}
   {
   const BigInt k = blinding_nonce();
   m_e = m_fwd_fn(k);
   m_d = m_inv_fn(k);
   }

BigInt Blinder::blinding_nonce() const
   {
   return BigInt(m_rng, m_modulus_bits - 1);
   }

BigInt Blinder::blind(const BigInt& i) const
   {
   if(!m_reducer.initialized())
      throw Exception("Blinder not initialized, cannot blind");

   ++m_counter;

   if((BOTAN_BLINDING_REINIT_INTERVAL > 0) && (m_counter > BOTAN_BLINDING_REINIT_INTERVAL))
      {
      const BigInt k = blinding_nonce();
      m_e = m_fwd_fn(k);
      m_d = m_inv_fn(k);
      m_counter = 0;
      }
   else
      {
      m_e = m_reducer.square(m_e);
      m_d = m_reducer.square(m_d);
      }

   return m_reducer.multiply(i, m_e);
   }

BigInt Blinder::unblind(const BigInt& i) const
   {
   if(!m_reducer.initialized())
      throw Exception("Blinder not initialized, cannot unblind");

   return m_reducer.multiply(i, m_d);
   }

}
/*
* PK Key
* (C) 1999-2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_RSA)
#endif

#if defined(BOTAN_HAS_DSA)
#endif

#if defined(BOTAN_HAS_DL_GROUP)
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
#endif

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
#endif

#if defined(BOTAN_HAS_ECDSA)
#endif

#if defined(BOTAN_HAS_ECGDSA)
#endif

#if defined(BOTAN_HAS_ECKCDSA)
#endif

#if defined(BOTAN_HAS_ED25519)
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
#endif

#if defined(BOTAN_HAS_ELGAMAL)
#endif

#if defined(BOTAN_HAS_ECDH)
#endif

#if defined(BOTAN_HAS_CURVE_25519)
#endif

#if defined(BOTAN_HAS_MCELIECE)
#endif

#if defined(BOTAN_HAS_XMSS)
#endif

#if defined(BOTAN_HAS_SM2)
#endif

#if defined(BOTAN_HAS_OPENSSL)
#endif

namespace Botan {

std::unique_ptr<Public_Key>
load_public_key(const AlgorithmIdentifier& alg_id,
                const std::vector<uint8_t>& key_bits)
   {
   const std::vector<std::string> alg_info = split_on(OIDS::lookup(alg_id.oid), '/');

   if(alg_info.empty())
      throw Decoding_Error("Unknown algorithm OID: " + alg_id.oid.as_string());

   const std::string alg_name = alg_info[0];

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA")
      return std::unique_ptr<Public_Key>(new RSA_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_CURVE_25519)
   if(alg_name == "Curve25519")
      return std::unique_ptr<Public_Key>(new Curve25519_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece")
      return std::unique_ptr<Public_Key>(new McEliece_PublicKey(key_bits));
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA")
      return std::unique_ptr<Public_Key>(new ECDSA_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH")
      return std::unique_ptr<Public_Key>(new ECDH_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH")
      return std::unique_ptr<Public_Key>(new DH_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA")
      return std::unique_ptr<Public_Key>(new DSA_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(alg_name == "ElGamal")
      return std::unique_ptr<Public_Key>(new ElGamal_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECGDSA)
   if(alg_name == "ECGDSA")
      return std::unique_ptr<Public_Key>(new ECGDSA_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECKCDSA)
   if(alg_name == "ECKCDSA")
      return std::unique_ptr<Public_Key>(new ECKCDSA_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ED25519)
   if(alg_name == "Ed25519")
      return std::unique_ptr<Public_Key>(new Ed25519_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10")
      return std::unique_ptr<Public_Key>(new GOST_3410_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_SM2)
   if(alg_name == "SM2_Sig")
      return std::unique_ptr<Public_Key>(new SM2_Signature_PublicKey(alg_id, key_bits));
   if(alg_name == "SM2_Enc")
      return std::unique_ptr<Public_Key>(new SM2_Encryption_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_XMSS)
   if(alg_name == "XMSS")
      return std::unique_ptr<Public_Key>(new XMSS_PublicKey(key_bits));
#endif

   throw Decoding_Error("Unhandled PK algorithm " + alg_name);
   }

std::unique_ptr<Private_Key>
load_private_key(const AlgorithmIdentifier& alg_id,
                 const secure_vector<uint8_t>& key_bits)
   {
   const std::string alg_name = OIDS::lookup(alg_id.oid);
   if(alg_name == "")
      throw Decoding_Error("Unknown algorithm OID: " + alg_id.oid.as_string());

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA")
      return std::unique_ptr<Private_Key>(new RSA_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_CURVE_25519)
   if(alg_name == "Curve25519")
      return std::unique_ptr<Private_Key>(new Curve25519_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA")
      return std::unique_ptr<Private_Key>(new ECDSA_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH")
      return std::unique_ptr<Private_Key>(new ECDH_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH")
      return std::unique_ptr<Private_Key>(new DH_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA")
      return std::unique_ptr<Private_Key>(new DSA_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece")
      return std::unique_ptr<Private_Key>(new McEliece_PrivateKey(key_bits));
#endif

#if defined(BOTAN_HAS_ECGDSA)
   if(alg_name == "ECGDSA")
      return std::unique_ptr<Private_Key>(new ECGDSA_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECKCDSA)
   if(alg_name == "ECKCDSA")
      return std::unique_ptr<Private_Key>(new ECKCDSA_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ED25519)
   if(alg_name == "Ed25519")
      return std::unique_ptr<Private_Key>(new Ed25519_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10")
      return std::unique_ptr<Private_Key>(new GOST_3410_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_SM2)
   if(alg_name == "SM2_Sig")
      return std::unique_ptr<Private_Key>(new SM2_Signature_PrivateKey(alg_id, key_bits));
   if(alg_name == "SM2_Enc")
      return std::unique_ptr<Private_Key>(new SM2_Encryption_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(alg_name == "ElGamal")
      return std::unique_ptr<Private_Key>(new ElGamal_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_XMSS)
   if(alg_name == "XMSS")
      return std::unique_ptr<Private_Key>(new XMSS_PrivateKey(key_bits));
#endif

   throw Decoding_Error("Unhandled PK algorithm " + alg_name);
   }

namespace {

std::string default_ec_group_for(const std::string& alg_name)
   {
   if(alg_name == "SM2_Enc" || alg_name == "SM2_Sig")
      return "sm2p256v1";
   if(alg_name == "GOST-34.10")
      return "gost_256A";
   if(alg_name == "ECGDSA")
      return "brainpool256r1";
   return "secp256r1";

   }

}

std::unique_ptr<Private_Key>
create_private_key(const std::string& alg_name,
                   RandomNumberGenerator& rng,
                   const std::string& params,
                   const std::string& provider)
   {
   /*
   * Default paramaters are chosen for work factor > 2**128 where possible
   */

#if defined(BOTAN_HAS_CURVE_25519)
   if(alg_name == "Curve25519")
      return std::unique_ptr<Private_Key>(new Curve25519_PrivateKey(rng));
#endif

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA")
      {
      const size_t rsa_bits = (params.empty() ? 3072 : to_u32bit(params));
#if defined(BOTAN_HAS_OPENSSL)
      if(provider.empty() || provider == "openssl")
         {
         std::unique_ptr<Botan::Private_Key> pk;
         if((pk = make_openssl_rsa_private_key(rng, rsa_bits)))
            return pk;

         if(!provider.empty())
            return nullptr;
         }
#endif
      return std::unique_ptr<Private_Key>(new RSA_PrivateKey(rng, rsa_bits));
      }
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece")
      {
      std::vector<std::string> mce_param =
         Botan::split_on(params.empty() ? "2960,57" : params, ',');

      if(mce_param.size() != 2)
         throw Invalid_Argument("create_private_key bad McEliece parameters " + params);

      size_t mce_n = Botan::to_u32bit(mce_param[0]);
      size_t mce_t = Botan::to_u32bit(mce_param[1]);

      return std::unique_ptr<Botan::Private_Key>(new Botan::McEliece_PrivateKey(rng, mce_n, mce_t));
      }
#endif

#if defined(BOTAN_HAS_XMSS)
   if(alg_name == "XMSS")
      {
      return std::unique_ptr<Private_Key>(
         new XMSS_PrivateKey(XMSS_Parameters(params.empty() ? "XMSS_SHA2-512_W16_H10" : params).oid(), rng));
      }
#endif

#if defined(BOTAN_HAS_ED25519)
   if(alg_name == "Ed25519")
      {
      return std::unique_ptr<Private_Key>(new Ed25519_PrivateKey(rng));
      }
#endif

   // ECC crypto
#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)

   if(alg_name == "ECDSA" ||
      alg_name == "ECDH" ||
      alg_name == "ECKCDSA" ||
      alg_name == "ECGDSA" ||
      alg_name == "SM2_Sig" ||
      alg_name == "SM2_Enc" ||
      alg_name == "GOST-34.10")
      {
      const EC_Group ec_group(params.empty() ? default_ec_group_for(alg_name) : params);

#if defined(BOTAN_HAS_ECDSA)
      if(alg_name == "ECDSA")
         return std::unique_ptr<Private_Key>(new ECDSA_PrivateKey(rng, ec_group));
#endif

#if defined(BOTAN_HAS_ECDH)
      if(alg_name == "ECDH")
         return std::unique_ptr<Private_Key>(new ECDH_PrivateKey(rng, ec_group));
#endif

#if defined(BOTAN_HAS_ECKCDSA)
      if(alg_name == "ECKCDSA")
         return std::unique_ptr<Private_Key>(new ECKCDSA_PrivateKey(rng, ec_group));
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
      if(alg_name == "GOST-34.10")
         return std::unique_ptr<Private_Key>(new GOST_3410_PrivateKey(rng, ec_group));
#endif

#if defined(BOTAN_HAS_SM2)
      if(alg_name == "SM2_Sig")
         return std::unique_ptr<Private_Key>(new SM2_Signature_PrivateKey(rng, ec_group));
      if(alg_name == "SM2_Enc")
         return std::unique_ptr<Private_Key>(new SM2_Encryption_PrivateKey(rng, ec_group));
#endif

#if defined(BOTAN_HAS_ECGDSA)
      if(alg_name == "ECGDSA")
         return std::unique_ptr<Private_Key>(new ECGDSA_PrivateKey(rng, ec_group));
#endif
      }
#endif

   // DL crypto
#if defined(BOTAN_HAS_DL_GROUP)
   if(alg_name == "DH" || alg_name == "DSA" || alg_name == "ElGamal")
      {
      std::string default_group = (alg_name == "DSA") ? "dsa/botan/2048" : "modp/ietf/2048";
      DL_Group modp_group(params.empty() ? default_group : params);

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
      if(alg_name == "DH")
         return std::unique_ptr<Private_Key>(new DH_PrivateKey(rng, modp_group));
#endif

#if defined(BOTAN_HAS_DSA)
      if(alg_name == "DSA")
         return std::unique_ptr<Private_Key>(new DSA_PrivateKey(rng, modp_group));
#endif

#if defined(BOTAN_HAS_ELGAMAL)
      if(alg_name == "ElGamal")
         return std::unique_ptr<Private_Key>(new ElGamal_PrivateKey(rng, modp_group));
#endif
      }
#endif

   BOTAN_UNUSED(alg_name, rng, provider);

   return std::unique_ptr<Private_Key>();
   }

std::vector<std::string>
probe_provider_private_key(const std::string& alg_name,
                           const std::vector<std::string> possible)
   {
   std::vector<std::string> providers;
   for(auto&& prov : possible)
      {
      if(prov == "base" ||
#if defined(BOTAN_HAS_OPENSSL)
         (prov == "openssl" && alg_name == "RSA") ||
#endif
         0)
         {
         providers.push_back(prov); // available
         }
      }

   BOTAN_UNUSED(alg_name);

   return providers;
   }
}
/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

std::vector<uint8_t> Public_Key::subject_public_key() const
   {
   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(algorithm_identifier())
            .encode(public_key_bits(), BIT_STRING)
         .end_cons()
      .get_contents_unlocked();
   }

/*
* Default OID access
*/
OID Public_Key::get_oid() const
   {
   try {
      return OIDS::lookup(algo_name());
      }
   catch(Lookup_Error&)
      {
      throw Lookup_Error("PK algo " + algo_name() + " has no defined OIDs");
      }
   }

secure_vector<uint8_t> Private_Key::private_key_info() const
   {
   const size_t PKCS8_VERSION = 0;

   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(PKCS8_VERSION)
            .encode(pkcs8_algorithm_identifier())
            .encode(private_key_bits(), OCTET_STRING)
         .end_cons()
      .get_contents();
   }

/*
* Hash of the PKCS #8 encoding for this key object
*/
std::string Private_Key::fingerprint(const std::string& alg) const
   {
   secure_vector<uint8_t> buf = private_key_bits();
   std::unique_ptr<HashFunction> hash(HashFunction::create(alg));
   hash->update(buf);
   const auto hex_print = hex_encode(hash->final());

   std::string formatted_print;

   for(size_t i = 0; i != hex_print.size(); i += 2)
      {
      formatted_print.push_back(hex_print[i]);
      formatted_print.push_back(hex_print[i+1]);

      if(i != hex_print.size() - 2)
         formatted_print.push_back(':');
      }

   return formatted_print;
   }

std::unique_ptr<PK_Ops::Encryption>
Public_Key::create_encryption_op(RandomNumberGenerator& /*rng*/,
                                 const std::string& /*params*/,
                                 const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support encryption");
   }

std::unique_ptr<PK_Ops::KEM_Encryption>
Public_Key::create_kem_encryption_op(RandomNumberGenerator& /*rng*/,
                                     const std::string& /*params*/,
                                     const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support KEM encryption");
   }

std::unique_ptr<PK_Ops::Verification>
Public_Key::create_verification_op(const std::string& /*params*/,
                                   const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support verification");
   }

std::unique_ptr<PK_Ops::Decryption>
Private_Key::create_decryption_op(RandomNumberGenerator& /*rng*/,
                                  const std::string& /*params*/,
                                  const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support decryption");
   }

std::unique_ptr<PK_Ops::KEM_Decryption>
Private_Key::create_kem_decryption_op(RandomNumberGenerator& /*rng*/,
                                      const std::string& /*params*/,
                                      const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support KEM decryption");
   }

std::unique_ptr<PK_Ops::Signature>
Private_Key::create_signature_op(RandomNumberGenerator& /*rng*/,
                                 const std::string& /*params*/,
                                 const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support signatures");
   }

std::unique_ptr<PK_Ops::Key_Agreement>
Private_Key::create_key_agreement_op(RandomNumberGenerator& /*rng*/,
                                     const std::string& /*params*/,
                                     const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support key agreement");
   }

}
/*
* PK Operation Types
* (C) 2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

PK_Ops::Encryption_with_EME::Encryption_with_EME(const std::string& eme)
   {
   m_eme.reset(get_eme(eme));
   if(!m_eme.get())
      throw Algorithm_Not_Found(eme);
   }

size_t PK_Ops::Encryption_with_EME::max_input_bits() const
   {
   return m_eme->maximum_input_size(max_raw_input_bits());
   }

secure_vector<uint8_t> PK_Ops::Encryption_with_EME::encrypt(const uint8_t msg[], size_t msg_len,
                                                         RandomNumberGenerator& rng)
   {
   const size_t max_raw = max_raw_input_bits();
   const std::vector<uint8_t> encoded = unlock(m_eme->encode(msg, msg_len, max_raw, rng));
   return raw_encrypt(encoded.data(), encoded.size(), rng);
   }

PK_Ops::Decryption_with_EME::Decryption_with_EME(const std::string& eme)
   {
   m_eme.reset(get_eme(eme));
   if(!m_eme.get())
      throw Algorithm_Not_Found(eme);
   }

secure_vector<uint8_t>
PK_Ops::Decryption_with_EME::decrypt(uint8_t& valid_mask,
                                     const uint8_t ciphertext[],
                                     size_t ciphertext_len)
   {
   const secure_vector<uint8_t> raw = raw_decrypt(ciphertext, ciphertext_len);
   return m_eme->unpad(valid_mask, raw.data(), raw.size());
   }

PK_Ops::Key_Agreement_with_KDF::Key_Agreement_with_KDF(const std::string& kdf)
   {
   if(kdf != "Raw")
      m_kdf.reset(get_kdf(kdf));
   }

secure_vector<uint8_t> PK_Ops::Key_Agreement_with_KDF::agree(size_t key_len,
                                                          const uint8_t w[], size_t w_len,
                                                          const uint8_t salt[], size_t salt_len)
   {
   secure_vector<uint8_t> z = raw_agree(w, w_len);
   if(m_kdf)
      return m_kdf->derive_key(key_len, z, salt, salt_len);
   return z;
  }

PK_Ops::Signature_with_EMSA::Signature_with_EMSA(const std::string& emsa) :
   Signature(),
   m_emsa(get_emsa(emsa)),
   m_hash(hash_for_emsa(emsa)),
   m_prefix_used(false)
   {
   if(!m_emsa)
      throw Algorithm_Not_Found(emsa);
   }

void PK_Ops::Signature_with_EMSA::update(const uint8_t msg[], size_t msg_len)
   {
   if(has_prefix() && !m_prefix_used)
      {
      m_prefix_used = true;
      secure_vector<uint8_t> prefix = message_prefix();
      m_emsa->update(prefix.data(), prefix.size());
      }
   m_emsa->update(msg, msg_len);
   }

secure_vector<uint8_t> PK_Ops::Signature_with_EMSA::sign(RandomNumberGenerator& rng)
   {
   m_prefix_used = false;
   const secure_vector<uint8_t> msg = m_emsa->raw_data();
   const auto padded = m_emsa->encoding_of(msg, this->max_input_bits(), rng);
   return raw_sign(padded.data(), padded.size(), rng);
   }

PK_Ops::Verification_with_EMSA::Verification_with_EMSA(const std::string& emsa) :
   Verification(),
   m_emsa(get_emsa(emsa)),
   m_hash(hash_for_emsa(emsa)),
   m_prefix_used(false)
   {
   if(!m_emsa)
      throw Algorithm_Not_Found(emsa);
   }

void PK_Ops::Verification_with_EMSA::update(const uint8_t msg[], size_t msg_len)
   {
   if(has_prefix() && !m_prefix_used)
      {
      m_prefix_used = true;
      secure_vector<uint8_t> prefix = message_prefix();
      m_emsa->update(prefix.data(), prefix.size());
      }
   m_emsa->update(msg, msg_len);
   }

bool PK_Ops::Verification_with_EMSA::is_valid_signature(const uint8_t sig[], size_t sig_len)
   {
   m_prefix_used = false;
   const secure_vector<uint8_t> msg = m_emsa->raw_data();

   if(with_recovery())
      {
      secure_vector<uint8_t> output_of_key = verify_mr(sig, sig_len);
      return m_emsa->verify(output_of_key, msg, max_input_bits());
      }
   else
      {
      Null_RNG rng;
      secure_vector<uint8_t> encoded = m_emsa->encoding_of(msg, max_input_bits(), rng);
      return verify(encoded.data(), encoded.size(), sig, sig_len);
      }
   }

void PK_Ops::KEM_Encryption_with_KDF::kem_encrypt(secure_vector<uint8_t>& out_encapsulated_key,
                                                  secure_vector<uint8_t>& out_shared_key,
                                                  size_t desired_shared_key_len,
                                                  Botan::RandomNumberGenerator& rng,
                                                  const uint8_t salt[],
                                                  size_t salt_len)
   {
   secure_vector<uint8_t> raw_shared;
   this->raw_kem_encrypt(out_encapsulated_key, raw_shared, rng);

   out_shared_key = m_kdf->derive_key(desired_shared_key_len,
                                      raw_shared.data(), raw_shared.size(),
                                      salt, salt_len);
   }

PK_Ops::KEM_Encryption_with_KDF::KEM_Encryption_with_KDF(const std::string& kdf)
   {
   m_kdf.reset(get_kdf(kdf));
   }

secure_vector<uint8_t>
PK_Ops::KEM_Decryption_with_KDF::kem_decrypt(const uint8_t encap_key[],
                                             size_t len,
                                             size_t desired_shared_key_len,
                                             const uint8_t salt[],
                                             size_t salt_len)
   {
   secure_vector<uint8_t> raw_shared = this->raw_kem_decrypt(encap_key, len);

   return m_kdf->derive_key(desired_shared_key_len,
                            raw_shared.data(), raw_shared.size(),
                            salt, salt_len);
   }

PK_Ops::KEM_Decryption_with_KDF::KEM_Decryption_with_KDF(const std::string& kdf)
   {
   m_kdf.reset(get_kdf(kdf));
   }

}
/*
* PKCS #8
* (C) 1999-2010,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace PKCS8 {

namespace {

/*
* Get info from an EncryptedPrivateKeyInfo
*/
secure_vector<uint8_t> PKCS8_extract(DataSource& source,
                                  AlgorithmIdentifier& pbe_alg_id)
   {
   secure_vector<uint8_t> key_data;

   BER_Decoder(source)
      .start_cons(SEQUENCE)
         .decode(pbe_alg_id)
         .decode(key_data, OCTET_STRING)
      .verify_end();

   return key_data;
   }

/*
* PEM decode and/or decrypt a private key
*/
secure_vector<uint8_t> PKCS8_decode(
   DataSource& source,
   std::function<std::string ()> get_passphrase,
   AlgorithmIdentifier& pk_alg_id,
   bool is_encrypted)
   {
   AlgorithmIdentifier pbe_alg_id;
   secure_vector<uint8_t> key_data, key;

   try {
      if(ASN1::maybe_BER(source) && !PEM_Code::matches(source))
         {
         if ( is_encrypted )
            {
            key_data = PKCS8_extract(source, pbe_alg_id);
            }
         else
            {
            // todo read more efficiently
            while ( !source.end_of_data() )
               {
               uint8_t b;
               size_t read = source.read_byte( b );
               if ( read )
                  {
                  key_data.push_back( b );
                  }
               }
            }
         }
      else
         {
         std::string label;
         key_data = PEM_Code::decode(source, label);

         // todo remove autodetect for pem as well?
         if(label == "PRIVATE KEY")
            is_encrypted = false;
         else if(label == "ENCRYPTED PRIVATE KEY")
            {
            DataSource_Memory key_source(key_data);
            key_data = PKCS8_extract(key_source, pbe_alg_id);
            }
         else
            throw PKCS8_Exception("Unknown PEM label " + label);
         }

      if(key_data.empty())
         throw PKCS8_Exception("No key data found");
      }
   catch(Decoding_Error& e)
      {
      throw Decoding_Error("PKCS #8 private key decoding failed: " + std::string(e.what()));
      }

   try
      {
      if(is_encrypted)
         {
         if(OIDS::lookup(pbe_alg_id.oid) != "PBE-PKCS5v20")
            throw Exception("Unknown PBE type " + pbe_alg_id.oid.as_string());
         key = pbes2_decrypt(key_data, get_passphrase(), pbe_alg_id.parameters);
         }
      else
         key = key_data;

      BER_Decoder(key)
         .start_cons(SEQUENCE)
         .decode_and_check<size_t>(0, "Unknown PKCS #8 version number")
            .decode(pk_alg_id)
            .decode(key, OCTET_STRING)
            .discard_remaining()
         .end_cons();
      }
   catch(std::exception& e)
      {
      throw Decoding_Error("PKCS #8 private key decoding failed: " + std::string(e.what()));
      }
   return key;
   }

}

/*
* BER encode a PKCS #8 private key, unencrypted
*/
secure_vector<uint8_t> BER_encode(const Private_Key& key)
   {
   // keeping around for compat
   return key.private_key_info();
   }

/*
* PEM encode a PKCS #8 private key, unencrypted
*/
std::string PEM_encode(const Private_Key& key)
   {
   return PEM_Code::encode(PKCS8::BER_encode(key), "PRIVATE KEY");
   }

namespace {

std::pair<std::string, std::string>
choose_pbe_params(const std::string& pbe_algo, const std::string& key_algo)
   {
   if(pbe_algo.empty())
      {
      // Defaults:
      if(key_algo == "Curve25519" || key_algo == "McEliece")
         return std::make_pair("AES-256/GCM", "SHA-512");
      else // for everything else (RSA, DSA, ECDSA, GOST, ...)
         return std::make_pair("AES-256/CBC", "SHA-256");
      }

   SCAN_Name request(pbe_algo);
   if(request.algo_name() != "PBE-PKCS5v20" || request.arg_count() != 2)
      throw Exception("Unsupported PBE " + pbe_algo);
   return std::make_pair(request.arg(1), request.arg(0));
   }

}

/*
* BER encode a PKCS #8 private key, encrypted
*/
std::vector<uint8_t> BER_encode(const Private_Key& key,
                             RandomNumberGenerator& rng,
                             const std::string& pass,
                             std::chrono::milliseconds msec,
                             const std::string& pbe_algo)
   {
   const auto pbe_params = choose_pbe_params(pbe_algo, key.algo_name());

   const std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pbe_info =
      pbes2_encrypt_msec(PKCS8::BER_encode(key), pass, msec, nullptr,
                         pbe_params.first, pbe_params.second, rng);

   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(pbe_info.first)
            .encode(pbe_info.second, OCTET_STRING)
         .end_cons()
      .get_contents_unlocked();
   }

/*
* PEM encode a PKCS #8 private key, encrypted
*/
std::string PEM_encode(const Private_Key& key,
                       RandomNumberGenerator& rng,
                       const std::string& pass,
                       std::chrono::milliseconds msec,
                       const std::string& pbe_algo)
   {
   if(pass.empty())
      return PEM_encode(key);

   return PEM_Code::encode(PKCS8::BER_encode(key, rng, pass, msec, pbe_algo),
                           "ENCRYPTED PRIVATE KEY");
   }

/*
* BER encode a PKCS #8 private key, encrypted
*/
std::vector<uint8_t> BER_encode_encrypted_pbkdf_iter(const Private_Key& key,
                                                     RandomNumberGenerator& rng,
                                                     const std::string& pass,
                                                     size_t pbkdf_iterations,
                                                     const std::string& cipher,
                                                     const std::string& pbkdf_hash)
   {
   const std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pbe_info =
      pbes2_encrypt_iter(key.private_key_info(),
                         pass, pbkdf_iterations,
                         cipher.empty() ? "AES-256/CBC" : cipher,
                         pbkdf_hash.empty() ? "SHA-256" : pbkdf_hash,
                         rng);

   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(pbe_info.first)
            .encode(pbe_info.second, OCTET_STRING)
         .end_cons()
      .get_contents_unlocked();
   }

/*
* PEM encode a PKCS #8 private key, encrypted
*/
std::string PEM_encode_encrypted_pbkdf_iter(const Private_Key& key,
                                            RandomNumberGenerator& rng,
                                            const std::string& pass,
                                            size_t pbkdf_iterations,
                                            const std::string& cipher,
                                            const std::string& pbkdf_hash)
   {
   return PEM_Code::encode(
      PKCS8::BER_encode_encrypted_pbkdf_iter(key, rng, pass, pbkdf_iterations, cipher, pbkdf_hash),
      "ENCRYPTED PRIVATE KEY");
   }

/*
* BER encode a PKCS #8 private key, encrypted
*/
std::vector<uint8_t> BER_encode_encrypted_pbkdf_msec(const Private_Key& key,
                                                     RandomNumberGenerator& rng,
                                                     const std::string& pass,
                                                     std::chrono::milliseconds pbkdf_msec,
                                                     size_t* pbkdf_iterations,
                                                     const std::string& cipher,
                                                     const std::string& pbkdf_hash)
   {
   const std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pbe_info =
      pbes2_encrypt_msec(key.private_key_info(), pass,
                         pbkdf_msec, pbkdf_iterations,
                         cipher.empty() ? "AES-256/CBC" : cipher,
                         pbkdf_hash.empty() ? "SHA-256" : pbkdf_hash,
                         rng);

   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(pbe_info.first)
            .encode(pbe_info.second, OCTET_STRING)
         .end_cons()
      .get_contents_unlocked();
   }

/*
* PEM encode a PKCS #8 private key, encrypted
*/
std::string PEM_encode_encrypted_pbkdf_msec(const Private_Key& key,
                                            RandomNumberGenerator& rng,
                                            const std::string& pass,
                                            std::chrono::milliseconds pbkdf_msec,
                                            size_t* pbkdf_iterations,
                                            const std::string& cipher,
                                            const std::string& pbkdf_hash)
   {
   return PEM_Code::encode(
      PKCS8::BER_encode_encrypted_pbkdf_msec(key, rng, pass, pbkdf_msec, pbkdf_iterations, cipher, pbkdf_hash),
      "ENCRYPTED PRIVATE KEY");
   }

namespace {

/*
* Extract a private key (encrypted/unencrypted) and return it
*/
std::unique_ptr<Private_Key>
load_key(DataSource& source,
         std::function<std::string ()> get_pass,
         bool is_encrypted)
   {
   AlgorithmIdentifier alg_id;
   secure_vector<uint8_t> pkcs8_key = PKCS8_decode(source, get_pass, alg_id, is_encrypted);

   const std::string alg_name = OIDS::lookup(alg_id.oid);
   if(alg_name.empty() || alg_name == alg_id.oid.as_string())
      throw PKCS8_Exception("Unknown algorithm OID: " +
                            alg_id.oid.as_string());

   return load_private_key(alg_id, pkcs8_key);
   }

}

/*
* Extract an encrypted private key and return it
*/
std::unique_ptr<Private_Key> load_key(DataSource& source,
                      std::function<std::string ()> get_pass)
   {
   return load_key(source, get_pass, true);
   }

/*
* Extract an encrypted private key and return it
*/
std::unique_ptr<Private_Key> load_key(DataSource& source,
                      const std::string& pass)
   {
   return load_key(source, [pass]() { return pass; }, true);
   }

/*
* Extract an unencrypted private key and return it
*/
std::unique_ptr<Private_Key> load_key(DataSource& source)
   {
   auto fail_fn = []() -> std::string {
      throw PKCS8_Exception("Internal error: Attempt to read password for unencrypted key");
   };

   return load_key(source, fail_fn, false);
   }

/*
* Make a copy of this private key
*/
std::unique_ptr<Private_Key> copy_key(const Private_Key& key)
   {
   DataSource_Memory source(PEM_encode(key));
   return PKCS8::load_key(source);
   }

/*
* Extract an encrypted private key and return it
*/
Private_Key* load_key(DataSource& source,
                      RandomNumberGenerator& rng,
                      std::function<std::string ()> get_pass)
   {
   BOTAN_UNUSED(rng);
   return PKCS8::load_key(source, get_pass).release();
   }

/*
* Extract an encrypted private key and return it
*/
Private_Key* load_key(DataSource& source,
                      RandomNumberGenerator& rng,
                      const std::string& pass)
   {
   BOTAN_UNUSED(rng);
   return PKCS8::load_key(source, pass).release();
   }

/*
* Extract an unencrypted private key and return it
*/
Private_Key* load_key(DataSource& source,
                      RandomNumberGenerator& rng)
   {
   BOTAN_UNUSED(rng);
   return PKCS8::load_key(source).release();
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

/*
* Extract an encrypted private key and return it
*/
Private_Key* load_key(const std::string& fsname,
                      RandomNumberGenerator& rng,
                      std::function<std::string ()> get_pass)
   {
   BOTAN_UNUSED(rng);
   DataSource_Stream in(fsname);
   return PKCS8::load_key(in, get_pass).release();
   }

/*
* Extract an encrypted private key and return it
*/
Private_Key* load_key(const std::string& fsname,
                      RandomNumberGenerator& rng,
                      const std::string& pass)
   {
   BOTAN_UNUSED(rng);
   DataSource_Stream in(fsname);
   return PKCS8::load_key(in, [pass]() { return pass; }).release();
   }

/*
* Extract an unencrypted private key and return it
*/
Private_Key* load_key(const std::string& fsname,
                      RandomNumberGenerator& rng)
   {
   BOTAN_UNUSED(rng);
   DataSource_Stream in(fsname);
   return PKCS8::load_key(in).release();
   }
#endif

/*
* Make a copy of this private key
*/
Private_Key* copy_key(const Private_Key& key,
                      RandomNumberGenerator& rng)
   {
   BOTAN_UNUSED(rng);
   return PKCS8::copy_key(key).release();
   }



}

}
/*
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

secure_vector<uint8_t> PK_Decryptor::decrypt(const uint8_t in[], size_t length) const
   {
   uint8_t valid_mask = 0;

   secure_vector<uint8_t> decoded = do_decrypt(valid_mask, in, length);

   if(valid_mask == 0)
      throw Decoding_Error("Invalid public key ciphertext, cannot decrypt");

   return decoded;
   }

secure_vector<uint8_t>
PK_Decryptor::decrypt_or_random(const uint8_t in[],
                                size_t length,
                                size_t expected_pt_len,
                                RandomNumberGenerator& rng,
                                const uint8_t required_content_bytes[],
                                const uint8_t required_content_offsets[],
                                size_t required_contents_length) const
   {
   const secure_vector<uint8_t> fake_pms = rng.random_vec(expected_pt_len);

   uint8_t valid_mask = 0;
   secure_vector<uint8_t> decoded = do_decrypt(valid_mask, in, length);

   valid_mask &= CT::is_equal(decoded.size(), expected_pt_len);

   decoded.resize(expected_pt_len);

   for(size_t i = 0; i != required_contents_length; ++i)
      {
      /*
      These values are chosen by the application and for TLS are constants,
      so this early failure via assert is fine since we know 0,1 < 48

      If there is a protocol that has content checks on the key where
      the expected offsets are controllable by the attacker this could
      still leak.

      Alternately could always reduce the offset modulo the length?
      */

      const uint8_t exp = required_content_bytes[i];
      const uint8_t off = required_content_offsets[i];

      BOTAN_ASSERT(off < expected_pt_len, "Offset in range of plaintext");

      valid_mask &= CT::is_equal(decoded[off], exp);
      }

   CT::conditional_copy_mem(valid_mask,
                            /*output*/decoded.data(),
                            /*from0*/decoded.data(),
                            /*from1*/fake_pms.data(),
                            expected_pt_len);

   return decoded;
   }

secure_vector<uint8_t>
PK_Decryptor::decrypt_or_random(const uint8_t in[],
                                size_t length,
                                size_t expected_pt_len,
                                RandomNumberGenerator& rng) const
   {
   return decrypt_or_random(in, length, expected_pt_len, rng,
                            nullptr, nullptr, 0);
   }

PK_Encryptor_EME::PK_Encryptor_EME(const Public_Key& key,
                                   RandomNumberGenerator& rng,
                                   const std::string& padding,
                                   const std::string& provider)
   {
   m_op = key.create_encryption_op(rng, padding, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support encryption");
   }

PK_Encryptor_EME::~PK_Encryptor_EME() { /* for unique_ptr */ }

std::vector<uint8_t>
PK_Encryptor_EME::enc(const uint8_t in[], size_t length, RandomNumberGenerator& rng) const
   {
   return unlock(m_op->encrypt(in, length, rng));
   }

size_t PK_Encryptor_EME::maximum_input_size() const
   {
   return m_op->max_input_bits() / 8;
   }

PK_Decryptor_EME::PK_Decryptor_EME(const Private_Key& key,
                                   RandomNumberGenerator& rng,
                                   const std::string& padding,
                                   const std::string& provider)
   {
   m_op = key.create_decryption_op(rng, padding, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support decryption");
   }

PK_Decryptor_EME::~PK_Decryptor_EME() { /* for unique_ptr */ }

secure_vector<uint8_t> PK_Decryptor_EME::do_decrypt(uint8_t& valid_mask,
                                                 const uint8_t in[], size_t in_len) const
   {
   return m_op->decrypt(valid_mask, in, in_len);
   }

PK_KEM_Encryptor::PK_KEM_Encryptor(const Public_Key& key,
                                   RandomNumberGenerator& rng,
                                   const std::string& param,
                                   const std::string& provider)
   {
   m_op = key.create_kem_encryption_op(rng, param, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support KEM encryption");
   }

PK_KEM_Encryptor::~PK_KEM_Encryptor() { /* for unique_ptr */ }

void PK_KEM_Encryptor::encrypt(secure_vector<uint8_t>& out_encapsulated_key,
                               secure_vector<uint8_t>& out_shared_key,
                               size_t desired_shared_key_len,
                               Botan::RandomNumberGenerator& rng,
                               const uint8_t salt[],
                               size_t salt_len)
   {
   m_op->kem_encrypt(out_encapsulated_key,
                     out_shared_key,
                     desired_shared_key_len,
                     rng,
                     salt,
                     salt_len);
   }

PK_KEM_Decryptor::PK_KEM_Decryptor(const Private_Key& key,
                                   RandomNumberGenerator& rng,
                                   const std::string& param,
                                   const std::string& provider)
   {
   m_op = key.create_kem_decryption_op(rng, param, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support KEM decryption");
   }

PK_KEM_Decryptor::~PK_KEM_Decryptor() { /* for unique_ptr */ }

secure_vector<uint8_t> PK_KEM_Decryptor::decrypt(const uint8_t encap_key[],
                                              size_t encap_key_len,
                                              size_t desired_shared_key_len,
                                              const uint8_t salt[],
                                              size_t salt_len)
   {
   return m_op->kem_decrypt(encap_key, encap_key_len,
                            desired_shared_key_len,
                            salt, salt_len);
   }

PK_Key_Agreement::PK_Key_Agreement(const Private_Key& key,
                                   RandomNumberGenerator& rng,
                                   const std::string& kdf,
                                   const std::string& provider)
   {
   m_op = key.create_key_agreement_op(rng, kdf, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support key agreement");
   }

PK_Key_Agreement::~PK_Key_Agreement() { /* for unique_ptr */ }

PK_Key_Agreement& PK_Key_Agreement::operator=(PK_Key_Agreement&& other)
   {
   if(this != &other)
      {
      m_op = std::move(other.m_op);
      }
   return (*this);
   }

PK_Key_Agreement::PK_Key_Agreement(PK_Key_Agreement&& other) :
   m_op(std::move(other.m_op))
   {}

SymmetricKey PK_Key_Agreement::derive_key(size_t key_len,
                                          const uint8_t in[], size_t in_len,
                                          const uint8_t salt[],
                                          size_t salt_len) const
   {
   return m_op->agree(key_len, in, in_len, salt, salt_len);
   }

PK_Signer::PK_Signer(const Private_Key& key,
                     RandomNumberGenerator& rng,
                     const std::string& emsa,
                     Signature_Format format,
                     const std::string& provider)
   {
   m_op = key.create_signature_op(rng, emsa, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support signature generation");
   m_sig_format = format;
   m_parts = key.message_parts();
   m_part_size = key.message_part_size();
   }

PK_Signer::~PK_Signer() { /* for unique_ptr */ }

void PK_Signer::update(const uint8_t in[], size_t length)
   {
   m_op->update(in, length);
   }

std::vector<uint8_t> PK_Signer::signature(RandomNumberGenerator& rng)
   {
   const std::vector<uint8_t> sig = unlock(m_op->sign(rng));

   if(m_sig_format == IEEE_1363)
      {
      return sig;
      }
   else if(m_sig_format == DER_SEQUENCE)
      {
      if(sig.size() % m_parts != 0 || sig.size() != m_parts * m_part_size)
         throw Internal_Error("PK_Signer: DER signature sizes unexpected, cannot encode");

      std::vector<BigInt> sig_parts(m_parts);
      for(size_t i = 0; i != sig_parts.size(); ++i)
         sig_parts[i].binary_decode(&sig[m_part_size*i], m_part_size);

      return DER_Encoder()
         .start_cons(SEQUENCE)
         .encode_list(sig_parts)
         .end_cons()
         .get_contents_unlocked();
      }
   else
      throw Internal_Error("PK_Signer: Invalid signature format enum");
   }

PK_Verifier::PK_Verifier(const Public_Key& key,
                         const std::string& emsa,
                         Signature_Format format,
                         const std::string& provider)
   {
   m_op = key.create_verification_op(emsa, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support signature verification");
   m_sig_format = format;
   m_parts = key.message_parts();
   m_part_size = key.message_part_size();
   }

PK_Verifier::~PK_Verifier() { /* for unique_ptr */ }

void PK_Verifier::set_input_format(Signature_Format format)
   {
   if(format != IEEE_1363 && m_parts == 1)
      throw Invalid_Argument("PK_Verifier: This algorithm does not support DER encoding");
   m_sig_format = format;
   }

bool PK_Verifier::verify_message(const uint8_t msg[], size_t msg_length,
                                 const uint8_t sig[], size_t sig_length)
   {
   update(msg, msg_length);
   return check_signature(sig, sig_length);
   }

void PK_Verifier::update(const uint8_t in[], size_t length)
   {
   m_op->update(in, length);
   }

bool PK_Verifier::check_signature(const uint8_t sig[], size_t length)
   {
   try {
      if(m_sig_format == IEEE_1363)
         {
         return m_op->is_valid_signature(sig, length);
         }
      else if(m_sig_format == DER_SEQUENCE)
         {
         std::vector<uint8_t> real_sig;
         BER_Decoder decoder(sig, length);
         BER_Decoder ber_sig = decoder.start_cons(SEQUENCE);

         size_t count = 0;
         while(ber_sig.more_items())
            {
            BigInt sig_part;
            ber_sig.decode(sig_part);
            real_sig += BigInt::encode_1363(sig_part, m_part_size);
            ++count;
            }

         if(count != m_parts)
            throw Decoding_Error("PK_Verifier: signature size invalid");

         return m_op->is_valid_signature(real_sig.data(), real_sig.size());
         }
      else
         throw Internal_Error("PK_Verifier: Invalid signature format enum");
      }
   catch(Invalid_Argument&) { return false; }
   }

}
/*
* Public Key Work Factor Functions
* (C) 1999-2007,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <cmath>

namespace Botan {

size_t ecp_work_factor(size_t bits)
   {
   return bits / 2;
   }

size_t if_work_factor(size_t bits)
   {
   // RFC 3766: k * e^((1.92 + o(1)) * cubrt(ln(n) * (ln(ln(n)))^2))
   // It estimates k at .02 and o(1) to be effectively zero for sizes of interest
   const double k = .02;

   // approximates natural logarithm of p
   const double log2_e = std::log2(std::exp(1));
   const double log_p = bits / log2_e;

   const double est = 1.92 * std::pow(log_p * std::log(log_p) * std::log(log_p), 1.0/3.0);

   return static_cast<size_t>(std::log2(k) + log2_e * est);
   }

size_t dl_work_factor(size_t bits)
   {
   // Lacking better estimates...
   return if_work_factor(bits);
   }

size_t dl_exponent_size(size_t bits)
   {
   /*
   This uses a slightly tweaked version of the standard work factor
   function above. It assumes k is 1 (thus overestimating the strength
   of the prime group by 5-6 bits), and always returns at least 128 bits
   (this only matters for very small primes).
   */
   const size_t MIN_WORKFACTOR = 64;
   const double log2_e = std::log2(std::exp(1));
   const double log_p = bits / log2_e;

   const double strength = 1.92 * std::pow(log_p, 1.0/3.0) * std::pow(std::log(log_p), 2.0/3.0);

   return 2 * std::max<size_t>(MIN_WORKFACTOR, static_cast<size_t>(log2_e * strength));
   }

}
/*
* X.509 Public Key
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace X509 {

std::vector<uint8_t> BER_encode(const Public_Key& key)
   {
   // keeping it around for compat
   return key.subject_public_key();
   }

/*
* PEM encode a X.509 public key
*/
std::string PEM_encode(const Public_Key& key)
   {
   return PEM_Code::encode(key.subject_public_key(),
                           "PUBLIC KEY");
   }

/*
* Extract a public key and return it
*/
Public_Key* load_key(DataSource& source)
   {
   try {
      AlgorithmIdentifier alg_id;
      std::vector<uint8_t> key_bits;

      if(ASN1::maybe_BER(source) && !PEM_Code::matches(source))
         {
         BER_Decoder(source)
            .start_cons(SEQUENCE)
            .decode(alg_id)
            .decode(key_bits, BIT_STRING)
         .end_cons();
         }
      else
         {
         DataSource_Memory ber(
            PEM_Code::decode_check_label(source, "PUBLIC KEY")
            );

         BER_Decoder(ber)
            .start_cons(SEQUENCE)
            .decode(alg_id)
            .decode(key_bits, BIT_STRING)
         .end_cons();
         }

      if(key_bits.empty())
         throw Decoding_Error("X.509 public key decoding failed");

      return load_public_key(alg_id, key_bits).release();
      }
   catch(Decoding_Error& e)
      {
      throw Decoding_Error("X.509 public key decoding failed: " + std::string(e.what()));
      }
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/*
* Extract a public key and return it
*/
Public_Key* load_key(const std::string& fsname)
   {
   DataSource_Stream source(fsname, true);
   return X509::load_key(source);
   }
#endif

/*
* Extract a public key and return it
*/
Public_Key* load_key(const std::vector<uint8_t>& mem)
   {
   DataSource_Memory source(mem);
   return X509::load_key(source);
   }

/*
* Make a copy of this public key
*/
Public_Key* copy_key(const Public_Key& key)
   {
   DataSource_Memory source(PEM_encode(key));
   return X509::load_key(source);
   }

}

}
/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
#endif

namespace Botan {

void RandomNumberGenerator::randomize_with_ts_input(uint8_t output[], size_t output_len)
   {
   /*
   Form additional input which is provided to the PRNG implementation
   to paramaterize the KDF output.
   */
   uint8_t additional_input[16] = { 0 };
   store_le(OS::get_system_timestamp_ns(), additional_input);
   store_le(OS::get_high_resolution_clock(), additional_input + 8);

   randomize_with_input(output, output_len, additional_input, sizeof(additional_input));
   }

void RandomNumberGenerator::randomize_with_input(uint8_t output[], size_t output_len,
                                                 const uint8_t input[], size_t input_len)
   {
   this->add_entropy(input, input_len);
   this->randomize(output, output_len);
   }

size_t RandomNumberGenerator::reseed(Entropy_Sources& srcs,
                                     size_t poll_bits,
                                     std::chrono::milliseconds poll_timeout)
   {
   return srcs.poll(*this, poll_bits, poll_timeout);
   }

void RandomNumberGenerator::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits)
   {
   secure_vector<uint8_t> buf(poll_bits / 8);
   rng.randomize(buf.data(), buf.size());
   this->add_entropy(buf.data(), buf.size());
   }

RandomNumberGenerator* RandomNumberGenerator::make_rng()
   {
#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   return new AutoSeeded_RNG;
#else
   throw Exception("make_rng failed, no AutoSeeded_RNG in this build");
#endif
   }

#if defined(BOTAN_TARGET_OS_HAS_THREADS)

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
Serialized_RNG::Serialized_RNG() : m_rng(new AutoSeeded_RNG) {}
#else
Serialized_RNG::Serialized_RNG()
   {
   throw Exception("Serialized_RNG default constructor failed: AutoSeeded_RNG disabled in build");
   }
#endif

#endif

}
/*
* SHA-{224,256}
* (C) 1999-2010,2017 Jack Lloyd
*     2007 FlexSecure GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

std::unique_ptr<HashFunction> SHA_224::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new SHA_224(*this));
   }

std::unique_ptr<HashFunction> SHA_256::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new SHA_256(*this));
   }

/*
* SHA-256 F1 Function
*
* Use a macro as many compilers won't inline a function this big,
* even though it is much faster if inlined.
*/
#define SHA2_32_F(A, B, C, D, E, F, G, H, M1, M2, M3, M4, magic) do {               \
   uint32_t A_rho = rotr<2>(A) ^ rotr<13>(A) ^ rotr<22>(A); \
   uint32_t E_rho = rotr<6>(E) ^ rotr<11>(E) ^ rotr<25>(E); \
   uint32_t M2_sigma = rotr<17>(M2) ^ rotr<19>(M2) ^ (M2 >> 10);    \
   uint32_t M4_sigma = rotr<7>(M4) ^ rotr<18>(M4) ^ (M4 >> 3);      \
   H += magic + E_rho + ((E & F) ^ (~E & G)) + M1;                                  \
   D += H;                                                                          \
   H += A_rho + ((A & B) | ((A | B) & C));                                          \
   M1 += M2_sigma + M3 + M4_sigma;                                                  \
   } while(0);

/*
* SHA-224 / SHA-256 compression function
*/
void SHA_256::compress_digest(secure_vector<uint32_t>& digest,
                              const uint8_t input[], size_t blocks)
   {
#if defined(BOTAN_HAS_SHA2_32_X86)
   if(CPUID::has_intel_sha())
      {
      return SHA_256::compress_digest_x86(digest, input, blocks);
      }
#endif

#if defined(BOTAN_HAS_SHA2_32_ARMV8)
   if(CPUID::has_arm_sha2())
      {
      return SHA_256::compress_digest_armv8(digest, input, blocks);
      }
#endif

   uint32_t A = digest[0], B = digest[1], C = digest[2],
          D = digest[3], E = digest[4], F = digest[5],
          G = digest[6], H = digest[7];

   for(size_t i = 0; i != blocks; ++i)
      {
      uint32_t W00 = load_be<uint32_t>(input,  0);
      uint32_t W01 = load_be<uint32_t>(input,  1);
      uint32_t W02 = load_be<uint32_t>(input,  2);
      uint32_t W03 = load_be<uint32_t>(input,  3);
      uint32_t W04 = load_be<uint32_t>(input,  4);
      uint32_t W05 = load_be<uint32_t>(input,  5);
      uint32_t W06 = load_be<uint32_t>(input,  6);
      uint32_t W07 = load_be<uint32_t>(input,  7);
      uint32_t W08 = load_be<uint32_t>(input,  8);
      uint32_t W09 = load_be<uint32_t>(input,  9);
      uint32_t W10 = load_be<uint32_t>(input, 10);
      uint32_t W11 = load_be<uint32_t>(input, 11);
      uint32_t W12 = load_be<uint32_t>(input, 12);
      uint32_t W13 = load_be<uint32_t>(input, 13);
      uint32_t W14 = load_be<uint32_t>(input, 14);
      uint32_t W15 = load_be<uint32_t>(input, 15);

      SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x428A2F98);
      SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x71374491);
      SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0xB5C0FBCF);
      SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0xE9B5DBA5);
      SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x3956C25B);
      SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x59F111F1);
      SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x923F82A4);
      SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0xAB1C5ED5);
      SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0xD807AA98);
      SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x12835B01);
      SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x243185BE);
      SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x550C7DC3);
      SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x72BE5D74);
      SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0x80DEB1FE);
      SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x9BDC06A7);
      SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0xC19BF174);
      SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0xE49B69C1);
      SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0xEFBE4786);
      SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x0FC19DC6);
      SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x240CA1CC);
      SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x2DE92C6F);
      SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x4A7484AA);
      SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x5CB0A9DC);
      SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x76F988DA);
      SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x983E5152);
      SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0xA831C66D);
      SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0xB00327C8);
      SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0xBF597FC7);
      SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0xC6E00BF3);
      SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xD5A79147);
      SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x06CA6351);
      SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x14292967);
      SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x27B70A85);
      SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x2E1B2138);
      SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x4D2C6DFC);
      SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x53380D13);
      SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x650A7354);
      SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x766A0ABB);
      SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x81C2C92E);
      SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x92722C85);
      SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0xA2BFE8A1);
      SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0xA81A664B);
      SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0xC24B8B70);
      SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0xC76C51A3);
      SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0xD192E819);
      SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xD6990624);
      SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0xF40E3585);
      SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x106AA070);
      SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x19A4C116);
      SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x1E376C08);
      SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x2748774C);
      SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x34B0BCB5);
      SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x391C0CB3);
      SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x4ED8AA4A);
      SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x5B9CCA4F);
      SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x682E6FF3);
      SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x748F82EE);
      SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x78A5636F);
      SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x84C87814);
      SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x8CC70208);
      SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x90BEFFFA);
      SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xA4506CEB);
      SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0xBEF9A3F7);
      SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0xC67178F2);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
      F = (digest[5] += F);
      G = (digest[6] += G);
      H = (digest[7] += H);

      input += 64;
      }
   }

/*
* SHA-224 compression function
*/
void SHA_224::compress_n(const uint8_t input[], size_t blocks)
   {
   SHA_256::compress_digest(m_digest, input, blocks);
   }

/*
* Copy out the digest
*/
void SHA_224::copy_out(uint8_t output[])
   {
   copy_out_vec_be(output, output_length(), m_digest);
   }

/*
* Clear memory of sensitive data
*/
void SHA_224::clear()
   {
   MDx_HashFunction::clear();
   m_digest[0] = 0xC1059ED8;
   m_digest[1] = 0x367CD507;
   m_digest[2] = 0x3070DD17;
   m_digest[3] = 0xF70E5939;
   m_digest[4] = 0xFFC00B31;
   m_digest[5] = 0x68581511;
   m_digest[6] = 0x64F98FA7;
   m_digest[7] = 0xBEFA4FA4;
   }

/*
* SHA-256 compression function
*/
void SHA_256::compress_n(const uint8_t input[], size_t blocks)
   {
   SHA_256::compress_digest(m_digest, input, blocks);
   }

/*
* Copy out the digest
*/
void SHA_256::copy_out(uint8_t output[])
   {
   copy_out_vec_be(output, output_length(), m_digest);
   }

/*
* Clear memory of sensitive data
*/
void SHA_256::clear()
   {
   MDx_HashFunction::clear();
   m_digest[0] = 0x6A09E667;
   m_digest[1] = 0xBB67AE85;
   m_digest[2] = 0x3C6EF372;
   m_digest[3] = 0xA54FF53A;
   m_digest[4] = 0x510E527F;
   m_digest[5] = 0x9B05688C;
   m_digest[6] = 0x1F83D9AB;
   m_digest[7] = 0x5BE0CD19;
   }

}
/*
* SRP-6a (RFC 5054 compatatible)
* (C) 2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

BigInt hash_seq(const std::string& hash_id,
                size_t pad_to,
                const BigInt& in1,
                const BigInt& in2)
   {
   std::unique_ptr<HashFunction> hash_fn(HashFunction::create_or_throw(hash_id));

   hash_fn->update(BigInt::encode_1363(in1, pad_to));
   hash_fn->update(BigInt::encode_1363(in2, pad_to));

   return BigInt::decode(hash_fn->final());
   }

BigInt compute_x(const std::string& hash_id,
                 const std::string& identifier,
                 const std::string& password,
                 const std::vector<uint8_t>& salt)
   {
   std::unique_ptr<HashFunction> hash_fn(HashFunction::create_or_throw(hash_id));

   hash_fn->update(identifier);
   hash_fn->update(":");
   hash_fn->update(password);

   secure_vector<uint8_t> inner_h = hash_fn->final();
   BigInt inner = BigInt::decode(inner_h);

   Botan::BigInt salt1 = Botan::BigInt::decode(salt);
   std::stringstream salt_str;
   salt_str << std::hex << salt1;


   std::stringstream inner_str;
   inner_str << std::hex << inner;

   hash_fn->update(salt_str.str());
   hash_fn->update(inner_str.str());

   secure_vector<uint8_t> outer_h = hash_fn->final();

   return BigInt::decode(outer_h);
   }

}

std::string srp6_group_identifier(const BigInt& N, const BigInt& g)
   {
   /*
   This function assumes that only one 'standard' SRP parameter set has
   been defined for a particular bitsize. As of this writing that is the case.
   */
   try
      {
      const std::string group_name = "modp/srp/" + std::to_string(N.bits());

      DL_Group group(group_name);

      if(group.get_p() == N && group.get_g() == g)
         return group_name;

      throw Exception("Unknown SRP params");
      }
   catch(...)
      {
      throw Invalid_Argument("Bad SRP group parameters");
      }
   }

std::pair<BigInt, SymmetricKey>
srp6_client_agree(const std::string& identifier,
                  const std::string& password,
                  const std::string& group_id,
                  const std::string& hash_id,
                  const std::vector<uint8_t>& salt,
                  const BigInt& B,
                  RandomNumberGenerator& rng)
   {
   DL_Group group(group_id);
   const BigInt& g = group.get_g();
   const BigInt& p = group.get_p();

   const size_t p_bytes = group.get_p().bytes();

   if(B <= 0 || B >= p)
      throw Exception("Invalid SRP parameter from server");

   BigInt k = hash_seq(hash_id, p_bytes, p, g);

   // BigInt a(rng, 256);
   BigInt a("0xc6f2fbbc4662d5489bb24b3520d77e10f06e226a813bbc022b1ea2fb21353352");

   // Hard Code Value
   BigInt A = power_mod(g, a, p);

   BigInt u = hash_seq(hash_id, p_bytes, A, B);

   std::unique_ptr<Botan::HashFunction> hash_fn(Botan::HashFunction::create_or_throw(hash_id));
   std::stringstream inner_str;
   inner_str << std::hex << A << B;
   hash_fn->update(inner_str.str());
   const Botan::BigInt uu = Botan::BigInt::decode(hash_fn->final());

   const BigInt x = compute_x(hash_id, identifier, password, salt);

   // std::cout << "---" << std::endl;
   // std::cout << "u: " << std::hex << uu << std::endl;
   // std::cout << "k: " << std::hex << k << std::endl;
   // std::cout << "x: " << std::hex << x << std::endl;
   // std::cout << "a: " << std::hex << a << std::endl;
   // std::cout << "B: " << std::hex << B << std::endl;
   // std::cout << "A: " << std::hex << A << std::endl;
   // std::cout << "---" << std::endl;

   BigInt exp = (a + (uu * x));
   BigInt tmp = (k * power_mod(g, x, p));
   BigInt tmp1 = (B - tmp);
   BigInt tmp2 = tmp1 % p;
   BigInt tmp11 = (tmp - B);
   BigInt tmp22 = tmp11 % p;

   // std::cout << "******" << std::endl;
   // std::cout << "p:  " << std::hex << p << std::endl;   
   // std::cout << "B:  " << std::hex << B << std::endl;   
   // std::cout << "exp: " << std::hex << exp << std::endl;   
   // std::cout << "expb: " << std::hex << expb << std::endl;   
   // std::cout << "tmp: " << std::hex << tmp << std::endl;   
   // std::cout << "tmp1: " << std::hex << tmp1 << std::endl;   
   // std::cout << "tmp2: " << std::hex << tmp2 << std::endl; 
   // std::cout << "tmp11: " << std::hex << tmp11 << std::endl;   
   // std::cout << "tmp11b: " << std::hex << tmp11b << std::endl;   
   // std::cout << "tmp22: " << std::hex << tmp22 << std::endl;   
   // std::cout << "******" << std::endl;
   BigInt S = power_mod(tmp2, exp, p);
   // std::cout << "client session key str: " << std::hex << S << std::endl;

   SymmetricKey Sk(BigInt::encode_1363(S, p_bytes));

   return std::make_pair(A, Sk);
   }

BigInt generate_srp6_verifier(const std::string& identifier,
                              const std::string& password,
                              const std::vector<uint8_t>& salt,
                              const std::string& group_id,
                              const std::string& hash_id)
   {
   const BigInt x = compute_x(hash_id, identifier, password, salt);

   DL_Group group(group_id);
   return power_mod(group.get_g(), x, group.get_p());
   }

BigInt SRP6_Server_Session::step1(const BigInt& v,
                                  const std::string& group_id,
                                  const std::string& hash_id,
                                  RandomNumberGenerator& rng)
   {
   DL_Group group(group_id);
   const BigInt& g = group.get_g();
   const BigInt& p = group.get_p();

   m_p_bytes = p.bytes();
   m_v = v;
   // m_b = BigInt(rng, 256);
   m_b = BigInt("0xE6EF737A1AEF514AE9D6620B2A6187F4A13058E3977E1D80AE2465588E24247C");
   // std::cout << "b: " << std::hex << m_b << std::endl;
   m_p = p;
   m_hash_id = hash_id;

   const BigInt k = hash_seq(hash_id, m_p_bytes, p, g);

   m_B = (v*k + power_mod(g, m_b, p)) % p;

   return m_B;
   }

SymmetricKey SRP6_Server_Session::step2(const BigInt& A)
   {
   if(A <= 0 || A >= m_p)
      throw Exception("Invalid SRP parameter from client");

   const BigInt u = hash_seq(m_hash_id, m_p_bytes, A, m_B);

   std::unique_ptr<Botan::HashFunction> hash_fn(Botan::HashFunction::create_or_throw(m_hash_id));
   std::stringstream inner_str;
   inner_str << std::hex << A << m_B;
   hash_fn->update(inner_str.str());
   const Botan::BigInt uu = Botan::BigInt::decode(hash_fn->final());

   const BigInt S = power_mod(A * power_mod(m_v, uu, m_p), m_b, m_p);
   // std::cout << "server session key str: " << std::hex << S << std::endl;

   return BigInt::encode_1363(S, m_p_bytes);
   }

}
/*
* Stream Ciphers
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_CHACHA)
#endif

#if defined(BOTAN_HAS_SALSA20)
#endif

#if defined(BOTAN_HAS_SHAKE_CIPHER)
#endif

#if defined(BOTAN_HAS_CTR_BE)
#endif

#if defined(BOTAN_HAS_OFB)
#endif

#if defined(BOTAN_HAS_RC4)
#endif

#if defined(BOTAN_HAS_OPENSSL)
#endif

namespace Botan {

std::unique_ptr<StreamCipher> StreamCipher::create(const std::string& algo_spec,
                                                   const std::string& provider)
   {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_CTR_BE)
   if((req.algo_name() == "CTR-BE" || req.algo_name() == "CTR") && req.arg_count_between(1,2))
      {
      if(provider.empty() || provider == "base")
         {
         auto cipher = BlockCipher::create(req.arg(0));
         if(cipher)
            {
            size_t ctr_size = req.arg_as_integer(1, cipher->block_size());
            return std::unique_ptr<StreamCipher>(new CTR_BE(cipher.release(), ctr_size));
            }
         }
      }
#endif

#if defined(BOTAN_HAS_CHACHA)
   if(req.algo_name() == "ChaCha")
      {
      if(provider.empty() || provider == "base")
         return std::unique_ptr<StreamCipher>(new ChaCha(req.arg_as_integer(0, 20)));
      }
#endif

#if defined(BOTAN_HAS_SALSA20)
   if(req.algo_name() == "Salsa20")
      {
      if(provider.empty() || provider == "base")
         return std::unique_ptr<StreamCipher>(new Salsa20);
      }
#endif

#if defined(BOTAN_HAS_SHAKE_CIPHER)
   if(req.algo_name() == "SHAKE-128")
      {
      if(provider.empty() || provider == "base")
         return std::unique_ptr<StreamCipher>(new SHAKE_128_Cipher);
      }
#endif

#if defined(BOTAN_HAS_OFB)
   if(req.algo_name() == "OFB" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         if(auto c = BlockCipher::create(req.arg(0)))
            return std::unique_ptr<StreamCipher>(new OFB(c.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_RC4)

   if(req.algo_name() == "RC4" ||
      req.algo_name() == "ARC4" ||
      req.algo_name() == "MARK-4")
      {
      const size_t skip = (req.algo_name() == "MARK-4") ? 256 : req.arg_as_integer(0, 0);

#if defined(BOTAN_HAS_OPENSSL)
      if(provider.empty() || provider == "openssl")
         {
         return std::unique_ptr<StreamCipher>(make_openssl_rc4(skip));
         }
#endif

      if(provider.empty() || provider == "base")
         {
         return std::unique_ptr<StreamCipher>(new RC4(skip));
         }
      }

#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
   }

//static
std::unique_ptr<StreamCipher>
StreamCipher::create_or_throw(const std::string& algo,
                             const std::string& provider)
   {
   if(auto sc = StreamCipher::create(algo, provider))
      {
      return sc;
      }
   throw Lookup_Error("Stream cipher", algo, provider);
   }

std::vector<std::string> StreamCipher::providers(const std::string& algo_spec)
   {
   return probe_providers_of<StreamCipher>(algo_spec, {"base", "openssl"});
   }

}
/*
* System RNG
* (C) 2014,2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)
   #define NOMINMAX 1
   #define _WINSOCKAPI_ // stop windows.h including winsock.h
   #include <windows.h>
   #include <wincrypt.h>

#elif defined(BOTAN_TARGET_OS_HAS_CRYPTO_NG)
   #include <bcrypt.h>

#elif defined(BOTAN_TARGET_OS_HAS_ARC4RANDOM)
   #include <stdlib.h>

#else
   #include <sys/types.h>
   #include <sys/stat.h>
   #include <fcntl.h>
   #include <unistd.h>
   #include <errno.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      System_RNG_Impl()
         {
         if(!CryptAcquireContext(&m_prov, nullptr, nullptr,
                                 BOTAN_SYSTEM_RNG_CRYPTOAPI_PROV_TYPE, CRYPT_VERIFYCONTEXT))
            throw Exception("System_RNG failed to acquire crypto provider");
         }

      ~System_RNG_Impl()
         {
         ::CryptReleaseContext(m_prov, 0);
         }

      void randomize(uint8_t buf[], size_t len) override
         {
         ::CryptGenRandom(m_prov, static_cast<DWORD>(len), buf);
         }

      void add_entropy(const uint8_t in[], size_t length) override
         {
         /*
         There is no explicit ConsumeRandom, but all values provided in
         the call are incorporated into the state.
         */
         std::vector<uint8_t> buf(in, in + length);
         ::CryptGenRandom(m_prov, static_cast<DWORD>(buf.size()), buf.data());
         }

      bool is_seeded() const override { return true; }
      void clear() override { /* not possible */ }
      std::string name() const override { return "cryptoapi"; }
   private:
      HCRYPTPROV m_prov;
   };

#elif defined(BOTAN_TARGET_OS_HAS_CRYPTO_NG)

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      System_RNG_Impl()
         {
         NTSTATUS ret = ::BCryptOpenAlgorithmProvider(&m_prov,
                                                      BCRYPT_RNG_ALGORITHM,
                                                      MS_PRIMITIVE_PROVIDER, 0);
         if(ret != STATUS_SUCCESS)
            throw Exception("System_RNG failed to acquire crypto provider");
         }

      ~System_RNG_Impl()
         {
         ::BCryptCloseAlgorithmProvider(m_prov, 0);
         }

      void randomize(uint8_t buf[], size_t len) override
         {
         ::BCryptGenRandom(m_prov, static_cast<PUCHAR>(buf), static_cast<ULONG>(len), 0);
         }

      void add_entropy(const uint8_t in[], size_t length) override
         {
         /*
         There is a flag BCRYPT_RNG_USE_ENTROPY_IN_BUFFER to provide
         entropy inputs, but it is ignored in Windows 8 and later.
         */
         }

      bool is_seeded() const override { return true; }
      void clear() override { /* not possible */ }
      std::string name() const override { return "crypto_ng"; }
   private:
      BCRYPT_ALG_HANDLE m_handle;
   };

#elif defined(BOTAN_TARGET_OS_HAS_ARC4RANDOM)

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      // No constructor or destructor needed as no userland state maintained

      void randomize(uint8_t buf[], size_t len) override
         {
         ::arc4random_buf(buf, len);
         }

      void add_entropy(const uint8_t[], size_t) override { /* ignored */ }
      bool is_seeded() const override { return true; }
      void clear() override { /* not possible */ }
      std::string name() const override { return "arc4random"; }
   };

#else

// Read a random device

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      System_RNG_Impl()
         {
         #ifndef O_NOCTTY
            #define O_NOCTTY 0
         #endif

         m_fd = ::open(BOTAN_SYSTEM_RNG_DEVICE, O_RDWR | O_NOCTTY);

         /*
         Cannot open in read-write mode. Fall back to read-only,
         calls to add_entropy will fail, but randomize will work
         */
         if(m_fd < 0)
            m_fd = ::open(BOTAN_SYSTEM_RNG_DEVICE, O_RDONLY | O_NOCTTY);

         if(m_fd < 0)
            throw Exception("System_RNG failed to open RNG device");
         }

      ~System_RNG_Impl()
         {
         ::close(m_fd);
         m_fd = -1;
         }

      void randomize(uint8_t buf[], size_t len) override;
      void add_entropy(const uint8_t in[], size_t length) override;
      bool is_seeded() const override { return true; }
      void clear() override { /* not possible */ }
      std::string name() const override { return BOTAN_SYSTEM_RNG_DEVICE; }
   private:
      int m_fd;
   };

void System_RNG_Impl::randomize(uint8_t buf[], size_t len)
   {
   while(len)
      {
      ssize_t got = ::read(m_fd, buf, len);

      if(got < 0)
         {
         if(errno == EINTR)
            continue;
         throw Exception("System_RNG read failed error " + std::to_string(errno));
         }
      if(got == 0)
         throw Exception("System_RNG EOF on device"); // ?!?

      buf += got;
      len -= got;
      }
   }

void System_RNG_Impl::add_entropy(const uint8_t input[], size_t len)
   {
   while(len)
      {
      ssize_t got = ::write(m_fd, input, len);

      if(got < 0)
         {
         if(errno == EINTR)
            continue;

         /*
         * This is seen on OS X CI, despite the fact that the man page
         * for Darwin urandom explicitly states that writing to it is
         * supported, and write(2) does not document EPERM at all.
         * But in any case EPERM seems indicative of a policy decision
         * by the OS or sysadmin that additional entropy is not wanted
         * in the system pool, so we accept that and return here,
         * since there is no corrective action possible.
	 *
	 * In Linux EBADF or EPERM is returned if m_fd is not opened for
	 * writing.
         */
         if(errno == EPERM || errno == EBADF)
            return;

         // maybe just ignore any failure here and return?
         throw Exception("System_RNG write failed error " + std::to_string(errno));
         }

      input += got;
      len -= got;
      }
   }

#endif

}

RandomNumberGenerator& system_rng()
   {
   static System_RNG_Impl g_system_rng;
   return g_system_rng;
   }

}
/*
* Runtime assertion checking
* (C) 2010,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

void assertion_failure(const char* expr_str,
                       const char* assertion_made,
                       const char* func,
                       const char* file,
                       int line)
   {
   std::ostringstream format;

   format << "False assertion ";

   if(assertion_made && assertion_made[0] != 0)
      format << "'" << assertion_made << "' (expression " << expr_str << ") ";
   else
      format << expr_str << " ";

   if(func)
      format << "in " << func << " ";

   format << "@" << file << ":" << line;

   throw Exception(format.str());
   }

}
/*
* Barrier
* (C) 2016 Joel Low
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_OS_HAS_THREADS)

namespace Botan {

void Barrier::wait(size_t delta)
    {
    lock_guard_type<mutex_type> lock(m_mutex);
    m_value += delta;
    }

void Barrier::sync()
    {
    std::unique_lock<mutex_type> lock(m_mutex);
    
    if(m_value > 1)
        {
        --m_value;
        const size_t current_syncs = m_syncs;
        m_cond.wait(lock, [this, &current_syncs] { return m_syncs != current_syncs; });
        }
    else
        {
        m_value = 0;
        ++m_syncs;
        m_cond.notify_all();
        }
    }

}

#endif
/*
* Calendar Functions
* (C) 1999-2010,2017 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <ctime>
#include <stdlib.h>

namespace Botan {

namespace {

std::tm do_gmtime(std::time_t time_val)
   {
   std::tm tm;

#if defined(BOTAN_TARGET_OS_HAS_GMTIME_S)
   ::gmtime_s(&tm, &time_val); // Windows
#elif defined(BOTAN_TARGET_OS_HAS_GMTIME_R)
   ::gmtime_r(&time_val, &tm); // Unix/SUSv2
#else
   std::tm* tm_p = std::gmtime(&time_val);
   if (tm_p == nullptr)
      throw Encoding_Error("time_t_to_tm could not convert");
   tm = *tm_p;
#endif

   return tm;
   }

/*
Portable replacement for timegm, _mkgmtime, etc

Algorithm due to Howard Hinnant

See https://howardhinnant.github.io/date_algorithms.html#days_from_civil
for details and explaination. The code is slightly simplified by our assumption
that the date is at least 1970, which is sufficient for our purposes.
*/
size_t days_since_epoch(uint32_t year, uint32_t month, uint32_t day)
   {
   if(month <= 2)
      year -= 1;
   const uint32_t era = year / 400;
   const uint32_t yoe = year - era * 400;      // [0, 399]
   const uint32_t doy = (153*(month + (month > 2 ? -3 : 9)) + 2)/5 + day-1;  // [0, 365]
   const uint32_t doe = yoe * 365 + yoe/4 - yoe/100 + doy;         // [0, 146096]
   return era * 146097 + doe - 719468;
   }

}

std::chrono::system_clock::time_point calendar_point::to_std_timepoint() const
   {
   if(get_year() < 1970)
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years before 1970");

   // 32 bit time_t ends at January 19, 2038
   // https://msdn.microsoft.com/en-us/library/2093ets1.aspx
   // Throw after 2037 if 32 bit time_t is used
   if(get_year() > 2037 && sizeof(std::time_t) == 4)
      {
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years after 2037 on this system");
      }
   else if(get_year() >= 2400)
      {
      // This upper bound is somewhat arbitrary
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years after 2400");
      }

   const uint64_t seconds_64 = (days_since_epoch(get_year(), get_month(), get_day()) * 86400) +
                                (get_hour() * 60 * 60) + (get_minutes() * 60) + get_seconds();

   const time_t seconds_time_t = static_cast<time_t>(seconds_64);

   if(seconds_64 - seconds_time_t != 0)
      {
      throw Invalid_Argument("calendar_point::to_std_timepoint time_t overflow");
      }

   return std::chrono::system_clock::from_time_t(seconds_time_t);
   }

std::string calendar_point::to_string() const
   {
   // desired format: <YYYY>-<MM>-<dd>T<HH>:<mm>:<ss>
   std::stringstream output;
   output << std::setfill('0')
          << std::setw(4) << get_year() << "-"
          << std::setw(2) << get_month() << "-"
          << std::setw(2) << get_day() << "T"
          << std::setw(2) << get_hour() << ":"
          << std::setw(2) << get_minutes() << ":"
          << std::setw(2) << get_seconds();
   return output.str();
   }


calendar_point calendar_value(
   const std::chrono::system_clock::time_point& time_point)
   {
   std::tm tm = do_gmtime(std::chrono::system_clock::to_time_t(time_point));

   return calendar_point(tm.tm_year + 1900,
                         tm.tm_mon + 1,
                         tm.tm_mday,
                         tm.tm_hour,
                         tm.tm_min,
                         tm.tm_sec);
   }

}
/*
* Character Set Handling
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

void append_utf8_for(std::string& s, uint32_t c)
   {
   if(c >= 0xD800 && c < 0xE000)
      throw Decoding_Error("Invalid Unicode character");

   if(c <= 0x7F)
      {
      const uint8_t b0 = static_cast<uint8_t>(c);
      s.push_back(static_cast<char>(b0));
      }
   else if(c <= 0x7FF)
      {
      const uint8_t b0 = 0xC0 | static_cast<uint8_t>(c >> 6);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
      }
   else if(c <= 0xFFFF)
      {
      const uint8_t b0 = 0xE0 | static_cast<uint8_t>(c >> 12);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>((c >> 6) & 0x3F);
      const uint8_t b2 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
      s.push_back(static_cast<char>(b2));
      }
   else if(c <= 0x10FFFF)
      {
      const uint8_t b0 = 0xF0 | static_cast<uint8_t>(c >> 18);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>((c >> 12) & 0x3F);
      const uint8_t b2 = 0x80 | static_cast<uint8_t>((c >> 6) & 0x3F);
      const uint8_t b3 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
      s.push_back(static_cast<char>(b2));
      s.push_back(static_cast<char>(b3));
      }
   else
      throw Decoding_Error("Invalid Unicode character");

   }

}

std::string ucs2_to_utf8(const uint8_t ucs2[], size_t len)
   {
   if(len % 2 != 0)
      throw Decoding_Error("Invalid length for UCS-2 string");

   const size_t chars = len / 2;

   std::string s;
   for(size_t i = 0; i != chars; ++i)
      {
      const uint16_t c = load_be<uint16_t>(ucs2, i);
      append_utf8_for(s, c);
      }

   return s;
   }

std::string ucs4_to_utf8(const uint8_t ucs4[], size_t len)
   {
   if(len % 4 != 0)
      throw Decoding_Error("Invalid length for UCS-4 string");

   const size_t chars = len / 4;

   std::string s;
   for(size_t i = 0; i != chars; ++i)
      {
      const uint32_t c = load_be<uint32_t>(ucs4, i);
      append_utf8_for(s, c);
      }

   return s;
   }

/*
* Convert from UTF-8 to ISO 8859-1
*/
std::string utf8_to_latin1(const std::string& utf8)
   {
   std::string iso8859;

   size_t position = 0;
   while(position != utf8.size())
      {
      const uint8_t c1 = static_cast<uint8_t>(utf8[position++]);

      if(c1 <= 0x7F)
         {
         iso8859 += static_cast<char>(c1);
         }
      else if(c1 >= 0xC0 && c1 <= 0xC7)
         {
         if(position == utf8.size())
            throw Decoding_Error("UTF-8: sequence truncated");

         const uint8_t c2 = static_cast<uint8_t>(utf8[position++]);
         const uint8_t iso_char = ((c1 & 0x07) << 6) | (c2 & 0x3F);

         if(iso_char <= 0x7F)
            throw Decoding_Error("UTF-8: sequence longer than needed");

         iso8859 += static_cast<char>(iso_char);
         }
      else
         throw Decoding_Error("UTF-8: Unicode chars not in Latin1 used");
      }

   return iso8859;
   }

namespace Charset {

namespace {

/*
* Convert from UCS-2 to ISO 8859-1
*/
std::string ucs2_to_latin1(const std::string& ucs2)
   {
   if(ucs2.size() % 2 == 1)
      throw Decoding_Error("UCS-2 string has an odd number of bytes");

   std::string latin1;

   for(size_t i = 0; i != ucs2.size(); i += 2)
      {
      const uint8_t c1 = ucs2[i];
      const uint8_t c2 = ucs2[i+1];

      if(c1 != 0)
         throw Decoding_Error("UCS-2 has non-Latin1 characters");

      latin1 += static_cast<char>(c2);
      }

   return latin1;
   }

/*
* Convert from ISO 8859-1 to UTF-8
*/
std::string latin1_to_utf8(const std::string& iso8859)
   {
   std::string utf8;
   for(size_t i = 0; i != iso8859.size(); ++i)
      {
      const uint8_t c = static_cast<uint8_t>(iso8859[i]);

      if(c <= 0x7F)
         utf8 += static_cast<char>(c);
      else
         {
         utf8 += static_cast<char>((0xC0 | (c >> 6)));
         utf8 += static_cast<char>((0x80 | (c & 0x3F)));
         }
      }
   return utf8;
   }

}

/*
* Perform character set transcoding
*/
std::string transcode(const std::string& str,
                      Character_Set to, Character_Set from)
   {
   if(to == LOCAL_CHARSET)
      to = LATIN1_CHARSET;
   if(from == LOCAL_CHARSET)
      from = LATIN1_CHARSET;

   if(to == from)
      return str;

   if(from == LATIN1_CHARSET && to == UTF8_CHARSET)
      return latin1_to_utf8(str);
   if(from == UTF8_CHARSET && to == LATIN1_CHARSET)
      return utf8_to_latin1(str);
   if(from == UCS2_CHARSET && to == LATIN1_CHARSET)
      return ucs2_to_latin1(str);

   throw Invalid_Argument("Unknown transcoding operation from " +
                          std::to_string(from) + " to " + std::to_string(to));
   }

/*
* Check if a character represents a digit
*/
bool is_digit(char c)
   {
   if(c == '0' || c == '1' || c == '2' || c == '3' || c == '4' ||
      c == '5' || c == '6' || c == '7' || c == '8' || c == '9')
      return true;
   return false;
   }

/*
* Check if a character represents whitespace
*/
bool is_space(char c)
   {
   if(c == ' ' || c == '\t' || c == '\n' || c == '\r')
      return true;
   return false;
   }

/*
* Convert a character to a digit
*/
uint8_t char2digit(char c)
   {
   switch(c)
      {
      case '0': return 0;
      case '1': return 1;
      case '2': return 2;
      case '3': return 3;
      case '4': return 4;
      case '5': return 5;
      case '6': return 6;
      case '7': return 7;
      case '8': return 8;
      case '9': return 9;
      }

   throw Invalid_Argument("char2digit: Input is not a digit character");
   }

/*
* Convert a digit to a character
*/
char digit2char(uint8_t b)
   {
   switch(b)
      {
      case 0: return '0';
      case 1: return '1';
      case 2: return '2';
      case 3: return '3';
      case 4: return '4';
      case 5: return '5';
      case 6: return '6';
      case 7: return '7';
      case 8: return '8';
      case 9: return '9';
      }

   throw Invalid_Argument("digit2char: Input is not a digit");
   }

/*
* Case-insensitive character comparison
*/
bool caseless_cmp(char a, char b)
   {
   return (std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b)));
   }

}

}
/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*     2005 Matthew Gregan
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
  #include <fstream>
#endif

namespace Botan {

/*
* Read a single byte from the DataSource
*/
size_t DataSource::read_byte(uint8_t& out)
   {
   return read(&out, 1);
   }

/*
* Peek a single byte from the DataSource
*/
size_t DataSource::peek_byte(uint8_t& out) const
   {
   return peek(&out, 1, 0);
   }

/*
* Discard the next N bytes of the data
*/
size_t DataSource::discard_next(size_t n)
   {
   uint8_t buf[64] = { 0 };
   size_t discarded = 0;

   while(n)
      {
      const size_t got = this->read(buf, std::min(n, sizeof(buf)));
      discarded += got;
      n -= got;

      if(got == 0)
         break;
      }

   return discarded;
   }

/*
* Read from a memory buffer
*/
size_t DataSource_Memory::read(uint8_t out[], size_t length)
   {
   size_t got = std::min<size_t>(m_source.size() - m_offset, length);
   copy_mem(out, m_source.data() + m_offset, got);
   m_offset += got;
   return got;
   }

bool DataSource_Memory::check_available(size_t n)
   {
   return (n <= (m_source.size() - m_offset));
   }

/*
* Peek into a memory buffer
*/
size_t DataSource_Memory::peek(uint8_t out[], size_t length,
                               size_t peek_offset) const
   {
   const size_t bytes_left = m_source.size() - m_offset;
   if(peek_offset >= bytes_left) return 0;

   size_t got = std::min(bytes_left - peek_offset, length);
   copy_mem(out, &m_source[m_offset + peek_offset], got);
   return got;
   }

/*
* Check if the memory buffer is empty
*/
bool DataSource_Memory::end_of_data() const
   {
   return (m_offset == m_source.size());
   }

/*
* DataSource_Memory Constructor
*/
DataSource_Memory::DataSource_Memory(const std::string& in) :
   m_source(cast_char_ptr_to_uint8(in.data()),
            cast_char_ptr_to_uint8(in.data()) + in.length()),
   m_offset(0)
   {
   }

/*
* Read from a stream
*/
size_t DataSource_Stream::read(uint8_t out[], size_t length)
   {
   m_source.read(cast_uint8_ptr_to_char(out), length);
   if(m_source.bad())
      throw Stream_IO_Error("DataSource_Stream::read: Source failure");

   const size_t got = static_cast<size_t>(m_source.gcount());
   m_total_read += got;
   return got;
   }

bool DataSource_Stream::check_available(size_t n)
   {
   const std::streampos orig_pos = m_source.tellg();
   m_source.seekg(0, std::ios::end);
   const size_t avail = static_cast<size_t>(m_source.tellg() - orig_pos);
   m_source.seekg(orig_pos);
   return (avail >= n);
   }

/*
* Peek into a stream
*/
size_t DataSource_Stream::peek(uint8_t out[], size_t length, size_t offset) const
   {
   if(end_of_data())
      throw Invalid_State("DataSource_Stream: Cannot peek when out of data");

   size_t got = 0;

   if(offset)
      {
      secure_vector<uint8_t> buf(offset);
      m_source.read(cast_uint8_ptr_to_char(buf.data()), buf.size());
      if(m_source.bad())
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      got = static_cast<size_t>(m_source.gcount());
      }

   if(got == offset)
      {
      m_source.read(cast_uint8_ptr_to_char(out), length);
      if(m_source.bad())
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      got = static_cast<size_t>(m_source.gcount());
      }

   if(m_source.eof())
      m_source.clear();
   m_source.seekg(m_total_read, std::ios::beg);

   return got;
   }

/*
* Check if the stream is empty or in error
*/
bool DataSource_Stream::end_of_data() const
   {
   return (!m_source.good());
   }

/*
* Return a human-readable ID for this stream
*/
std::string DataSource_Stream::id() const
   {
   return m_identifier;
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(const std::string& path,
                                     bool use_binary) :
   m_identifier(path),
   m_source_memory(new std::ifstream(path, use_binary ? std::ios::binary : std::ios::in)),
   m_source(*m_source_memory),
   m_total_read(0)
   {
   if(!m_source.good())
      {
      throw Stream_IO_Error("DataSource: Failure opening file " + path);
      }
   }

#endif

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(std::istream& in,
                                     const std::string& name) :
   m_identifier(name),
   m_source(in),
   m_total_read(0)
   {
   }

DataSource_Stream::~DataSource_Stream()
   {
   // for ~unique_ptr
   }

}
/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

Exception::Exception(const std::string& msg) : m_msg(msg)
   {}

Exception::Exception(const char* prefix, const std::string& msg) :
   m_msg(std::string(prefix) + " " + msg)
   {}

Invalid_Argument::Invalid_Argument(const std::string& msg) :
   Exception("Invalid argument", msg)
   {}

Invalid_Argument::Invalid_Argument(const std::string& msg, const std::string& where) :
   Exception("Invalid argument", msg + " in " + where)
   {}

Lookup_Error::Lookup_Error(const std::string& type,
                           const std::string& algo,
                           const std::string& provider) :
   Exception("Unavailable " + type + " " + algo +
             (provider.empty() ? std::string("") : (" for provider " + provider)))
   {}

Internal_Error::Internal_Error(const std::string& err) :
   Exception("Internal error: " + err)
   {}

Invalid_Key_Length::Invalid_Key_Length(const std::string& name, size_t length) :
   Invalid_Argument(name + " cannot accept a key of length " +
                    std::to_string(length))
   {}

Invalid_IV_Length::Invalid_IV_Length(const std::string& mode, size_t bad_len) :
   Invalid_Argument("IV length " + std::to_string(bad_len) +
                    " is invalid for " + mode)
   {}

Key_Not_Set::Key_Not_Set(const std::string& algo) :
   Invalid_State("Key not set in " + algo)
   {}

Policy_Violation::Policy_Violation(const std::string& err) :
   Invalid_State("Policy violation: " + err) {}

PRNG_Unseeded::PRNG_Unseeded(const std::string& algo) :
   Invalid_State("PRNG not seeded: " + algo)
   {}

Algorithm_Not_Found::Algorithm_Not_Found(const std::string& name) :
   Lookup_Error("Could not find any algorithm named \"" + name + "\"")
   {}

No_Provider_Found::No_Provider_Found(const std::string& name) :
   Exception("Could not find any provider for algorithm named \"" + name + "\"")
   {}

Provider_Not_Found::Provider_Not_Found(const std::string& algo, const std::string& provider) :
   Lookup_Error("Could not find provider '" + provider + "' for " + algo)
   {}

Invalid_Algorithm_Name::Invalid_Algorithm_Name(const std::string& name):
   Invalid_Argument("Invalid algorithm name: " + name)
   {}

Encoding_Error::Encoding_Error(const std::string& name) :
   Invalid_Argument("Encoding error: " + name)
   {}

Decoding_Error::Decoding_Error(const std::string& name) :
   Invalid_Argument("Decoding error: " + name)
   {}

Decoding_Error::Decoding_Error(const std::string& name, const char* exception_message) :
   Invalid_Argument("Decoding error: " + name + " failed with exception " + exception_message) {}

Integrity_Failure::Integrity_Failure(const std::string& msg) :
   Exception("Integrity failure: " + msg)
   {}

Invalid_OID::Invalid_OID(const std::string& oid) :
   Decoding_Error("Invalid ASN.1 OID: " + oid)
   {}

Stream_IO_Error::Stream_IO_Error(const std::string& err) :
   Exception("I/O error: " + err)
   {}

Self_Test_Failure::Self_Test_Failure(const std::string& err) :
   Internal_Error("Self test failed: " + err)
   {}

Not_Implemented::Not_Implemented(const std::string& err) :
   Exception("Not implemented", err)
   {}

}
/*
* (C) 2015,2017 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_OS_HAS_STL_FILESYSTEM_MSVC) && defined(BOTAN_BUILD_COMPILER_IS_MSVC)
  #include <filesystem>
#elif defined(BOTAN_HAS_BOOST_FILESYSTEM)
  #include <boost/filesystem.hpp>
#elif defined(BOTAN_TARGET_OS_HAS_READDIR)
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <dirent.h>
#elif defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)
  #define NOMINMAX 1
  #define _WINSOCKAPI_ // stop windows.h including winsock.h
  #include <windows.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_OS_HAS_STL_FILESYSTEM_MSVC) && defined(BOTAN_BUILD_COMPILER_IS_MSVC)
std::vector<std::string> impl_stl_filesystem(const std::string& dir)
   {
   using namespace std::tr2::sys;

   std::vector<std::string> out;

   path p(dir);

   if (is_directory(p))
      {
      for (recursive_directory_iterator itr(p), end; itr != end; ++itr)
         {
         if (is_regular_file(itr->path()))
            {
            out.push_back(itr->path().string());
            }
         }
      }

   return out;
   }

#elif defined(BOTAN_HAS_BOOST_FILESYSTEM)

std::vector<std::string> impl_boost_filesystem(const std::string& dir_path)
{
   namespace fs = boost::filesystem;

   std::vector<std::string> out;

   for(fs::recursive_directory_iterator dir(dir_path), end; dir != end; ++dir)
      {
      if(fs::is_regular_file(dir->path()))
         {
         out.push_back(dir->path().string());
         }
      }

   return out;
}

#elif defined(BOTAN_TARGET_OS_HAS_READDIR)
std::vector<std::string> impl_readdir(const std::string& dir_path)
   {
   std::vector<std::string> out;
   std::deque<std::string> dir_list;
   dir_list.push_back(dir_path);

   while(!dir_list.empty())
      {
      const std::string cur_path = dir_list[0];
      dir_list.pop_front();

      std::unique_ptr<DIR, std::function<int (DIR*)>> dir(::opendir(cur_path.c_str()), ::closedir);

      if(dir)
         {
         while(struct dirent* dirent = ::readdir(dir.get()))
            {
            const std::string filename = dirent->d_name;
            if(filename == "." || filename == "..")
               continue;
            const std::string full_path = cur_path + "/" + filename;

            struct stat stat_buf;

            if(::stat(full_path.c_str(), &stat_buf) == -1)
               continue;

            if(S_ISDIR(stat_buf.st_mode))
               dir_list.push_back(full_path);
            else if(S_ISREG(stat_buf.st_mode))
               out.push_back(full_path);
            }
         }
      }

   return out;
   }

#elif defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)

std::vector<std::string> impl_win32(const std::string& dir_path)
   {
   std::vector<std::string> out;
   std::deque<std::string> dir_list;
   dir_list.push_back(dir_path);

   while(!dir_list.empty())
      {
      const std::string cur_path = dir_list[0];
      dir_list.pop_front();

      WIN32_FIND_DATA find_data;
      HANDLE dir = ::FindFirstFile((cur_path + "/*").c_str(), &find_data);

      if(dir != INVALID_HANDLE_VALUE)
         {
         do
            {
            const std::string filename = find_data.cFileName;
            if(filename == "." || filename == "..")
               continue;
            const std::string full_path = cur_path + "/" + filename;

            if(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
               {
               dir_list.push_back(full_path);
               }
            else
               {
               out.push_back(full_path);
               }
            }
         while(::FindNextFile(dir, &find_data));
         }

      ::FindClose(dir);
      }

   return out;
}
#endif

}

std::vector<std::string> get_files_recursive(const std::string& dir)
   {
   std::vector<std::string> files;

#if defined(BOTAN_TARGET_OS_HAS_STL_FILESYSTEM_MSVC) && defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   files = impl_stl_filesystem(dir);
#elif defined(BOTAN_HAS_BOOST_FILESYSTEM)
   files = impl_boost_filesystem(dir);
#elif defined(BOTAN_TARGET_OS_HAS_READDIR)
   files = impl_readdir(dir);
#elif defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)
   files = impl_win32(dir);
#else
   BOTAN_UNUSED(dir);
   throw No_Filesystem_Access();
#endif

   std::sort(files.begin(), files.end());

   return files;
   }

}
/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <cstdlib>

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
#endif

namespace Botan {

BOTAN_MALLOC_FN void* allocate_memory(size_t elems, size_t elem_size)
   {
#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(void* p = mlock_allocator::instance().allocate(elems, elem_size))
      return p;
#endif

   void* ptr = std::calloc(elems, elem_size);
   if(!ptr)
      throw std::bad_alloc();
   return ptr;
   }

void deallocate_memory(void* p, size_t elems, size_t elem_size)
   {
   if(p == nullptr)
      return;

   secure_scrub_memory(p, elems * elem_size);

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(mlock_allocator::instance().deallocate(p, elems, elem_size))
      return;
#endif

   std::free(p);
   }

bool constant_time_compare(const uint8_t x[],
                           const uint8_t y[],
                           size_t len)
   {
   volatile uint8_t difference = 0;

   for(size_t i = 0; i != len; ++i)
      difference |= (x[i] ^ y[i]);

   return difference == 0;
   }

}
/*
* OS and machine specific utility functions
* (C) 2015,2016,2017 Jack Lloyd
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



#if defined(BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO)
  #include <string.h>
#endif

#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
  #include <sys/types.h>
  #include <sys/resource.h>
  #include <sys/mman.h>
  #include <signal.h>
  #include <setjmp.h>
  #include <unistd.h>
  #include <errno.h>
#elif defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)
  #define NOMINMAX 1
  #include <windows.h>
#endif

namespace Botan {

// Not defined in OS namespace for historical reasons
void secure_scrub_memory(void* ptr, size_t n)
   {
#if defined(BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
   ::RtlSecureZeroMemory(ptr, n);

#elif defined(BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO)
   ::explicit_bzero(ptr, n);

#elif defined(BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO) && (BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO == 1)
   /*
   Call memset through a static volatile pointer, which the compiler
   should not elide. This construct should be safe in conforming
   compilers, but who knows. I did confirm that on x86-64 GCC 6.1 and
   Clang 3.8 both create code that saves the memset address in the
   data segment and uncondtionally loads and jumps to that address.
   */
   static void* (*const volatile memset_ptr)(void*, int, size_t) = std::memset;
   (memset_ptr)(ptr, 0, n);
#else

   volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);

   for(size_t i = 0; i != n; ++i)
      p[i] = 0;
#endif
   }

uint32_t OS::get_process_id()
   {
#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
   return ::getpid();
#elif defined(BOTAN_TARGET_OS_IS_WINDOWS) || defined(BOTAN_TARGET_OS_IS_MINGW)
   return ::GetCurrentProcessId();
#elif defined(BOTAN_TARGET_OS_TYPE_IS_UNIKERNEL) || defined(BOTAN_TARGET_OS_IS_LLVM)
   return 0; // truly no meaningful value
#else
   #error "Missing get_process_id"
#endif
   }

uint64_t OS::get_processor_timestamp()
   {
   uint64_t rtc = 0;

#if defined(BOTAN_TARGET_OS_HAS_QUERY_PERF_COUNTER)
   LARGE_INTEGER tv;
   ::QueryPerformanceCounter(&tv);
   rtc = tv.QuadPart;

#elif defined(BOTAN_USE_GCC_INLINE_ASM)

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   if(CPUID::has_rdtsc())
      {
      uint32_t rtc_low = 0, rtc_high = 0;
      asm volatile("rdtsc" : "=d" (rtc_high), "=a" (rtc_low));
      rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
      }

#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
   uint32_t rtc_low = 0, rtc_high = 0;
   asm volatile("mftbu %0; mftb %1" : "=r" (rtc_high), "=r" (rtc_low));

   /*
   qemu-ppc seems to not support mftb instr, it always returns zero.
   If both time bases are 0, assume broken and return another clock.
   */
   if(rtc_high > 0 || rtc_low > 0)
      {
      rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
      }

#elif defined(BOTAN_TARGET_ARCH_IS_ALPHA)
   asm volatile("rpcc %0" : "=r" (rtc));

   // OpenBSD does not trap access to the %tick register
#elif defined(BOTAN_TARGET_ARCH_IS_SPARC64) && !defined(BOTAN_TARGET_OS_IS_OPENBSD)
   asm volatile("rd %%tick, %0" : "=r" (rtc));

#elif defined(BOTAN_TARGET_ARCH_IS_IA64)
   asm volatile("mov %0=ar.itc" : "=r" (rtc));

#elif defined(BOTAN_TARGET_ARCH_IS_S390X)
   asm volatile("stck 0(%0)" : : "a" (&rtc) : "memory", "cc");

#elif defined(BOTAN_TARGET_ARCH_IS_HPPA)
   asm volatile("mfctl 16,%0" : "=r" (rtc)); // 64-bit only?

#else
   //#warning "OS::get_processor_timestamp not implemented"
#endif

#endif

   return rtc;
   }

uint64_t OS::get_high_resolution_clock()
   {
   if(uint64_t cpu_clock = OS::get_processor_timestamp())
      return cpu_clock;

   /*
   If we got here either we either don't have an asm instruction
   above, or (for x86) RDTSC is not available at runtime. Try some
   clock_gettimes and return the first one that works, or otherwise
   fall back to std::chrono.
   */

#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)

   // The ordering here is somewhat arbitrary...
   const clockid_t clock_types[] = {
#if defined(CLOCK_MONOTONIC_HR)
      CLOCK_MONOTONIC_HR,
#endif
#if defined(CLOCK_MONOTONIC_RAW)
      CLOCK_MONOTONIC_RAW,
#endif
#if defined(CLOCK_MONOTONIC)
      CLOCK_MONOTONIC,
#endif
#if defined(CLOCK_PROCESS_CPUTIME_ID)
      CLOCK_PROCESS_CPUTIME_ID,
#endif
#if defined(CLOCK_THREAD_CPUTIME_ID)
      CLOCK_THREAD_CPUTIME_ID,
#endif
   };

   for(clockid_t clock : clock_types)
      {
      struct timespec ts;
      if(::clock_gettime(clock, &ts) == 0)
         {
         return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
         }
      }
#endif

   // Plain C++11 fallback
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
   }

uint64_t OS::get_system_timestamp_ns()
   {
#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)
   struct timespec ts;
   if(::clock_gettime(CLOCK_REALTIME, &ts) == 0)
      {
      return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
      }
#endif

   auto now = std::chrono::system_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
   }

size_t OS::get_memory_locking_limit()
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   /*
   * Linux defaults to only 64 KiB of mlockable memory per process
   * (too small) but BSDs offer a small fraction of total RAM (more
   * than we need). Bound the total mlock size to 512 KiB which is
   * enough to run the entire test suite without spilling to non-mlock
   * memory (and thus presumably also enough for many useful
   * programs), but small enough that we should not cause problems
   * even if many processes are mlocking on the same machine.
   */
   size_t mlock_requested = BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB;

   /*
   * Allow override via env variable
   */
   if(const char* env = std::getenv("BOTAN_MLOCK_POOL_SIZE"))
      {
      try
         {
         const size_t user_req = std::stoul(env, nullptr);
         mlock_requested = std::min(user_req, mlock_requested);
         }
      catch(std::exception&) { /* ignore it */ }
      }

#if defined(RLIMIT_MEMLOCK)
   if(mlock_requested > 0)
      {
      struct ::rlimit limits;

      ::getrlimit(RLIMIT_MEMLOCK, &limits);

      if(limits.rlim_cur < limits.rlim_max)
         {
         limits.rlim_cur = limits.rlim_max;
         ::setrlimit(RLIMIT_MEMLOCK, &limits);
         ::getrlimit(RLIMIT_MEMLOCK, &limits);
         }

      return std::min<size_t>(limits.rlim_cur, mlock_requested * 1024);
      }
#else
   /*
   * If RLIMIT_MEMLOCK is not defined, likely the OS does not support
   * unprivileged mlock calls.
   */
   return 0;
#endif

#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK) && defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   SIZE_T working_min = 0, working_max = 0;
   DWORD working_flags = 0;
   if(!::GetProcessWorkingSetSizeEx(::GetCurrentProcess(), &working_min, &working_max, &working_flags))
      {
      return 0;
      }

   SYSTEM_INFO sSysInfo;
   ::GetSystemInfo(&sSysInfo);

   // According to Microsoft MSDN:
   // The maximum number of pages that a process can lock is equal to the number of pages in its minimum working set minus a small overhead
   // In the book "Windows Internals Part 2": the maximum lockable pages are minimum working set size - 8 pages 
   // But the information in the book seems to be inaccurate/outdated
   // I've tested this on Windows 8.1 x64, Windows 10 x64 and Windows 7 x86
   // On all three OS the value is 11 instead of 8
   size_t overhead = sSysInfo.dwPageSize * 11ULL;
   if(working_min > overhead)
      {
      size_t lockable_bytes = working_min - overhead;
      if(lockable_bytes < (BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB * 1024ULL))
         {
         return lockable_bytes;
         }
      else
         {
         return BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB * 1024ULL;
         }
      }
#endif

   return 0;
   }

void* OS::allocate_locked_pages(size_t length)
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)

#if !defined(MAP_NOCORE)
   #define MAP_NOCORE 0
#endif

#if !defined(MAP_ANONYMOUS)
   #define MAP_ANONYMOUS MAP_ANON
#endif

   void* ptr = ::mmap(nullptr,
                      length,
                      PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE,
                      /*fd*/-1,
                      /*offset*/0);

   if(ptr == MAP_FAILED)
      {
      return nullptr;
      }

#if defined(MADV_DONTDUMP)
   ::madvise(ptr, length, MADV_DONTDUMP);
#endif

   if(::mlock(ptr, length) != 0)
      {
      ::munmap(ptr, length);
      return nullptr; // failed to lock
      }

   ::memset(ptr, 0, length);

   return ptr;
#elif defined BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK
   LPVOID ptr = ::VirtualAlloc(nullptr, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
   if(!ptr)
      {
      return nullptr;
      }

   if(::VirtualLock(ptr, length) == 0)
      {
      ::VirtualFree(ptr, 0, MEM_RELEASE);
      return nullptr; // failed to lock
      }

   return ptr;
#else
   BOTAN_UNUSED(length);
   return nullptr; /* not implemented */
#endif
   }

void OS::free_locked_pages(void* ptr, size_t length)
   {
   if(ptr == nullptr || length == 0)
      return;

#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   secure_scrub_memory(ptr, length);
   ::munlock(ptr, length);
   ::munmap(ptr, length);
#elif defined BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK
   secure_scrub_memory(ptr, length);
   ::VirtualUnlock(ptr, length);
   ::VirtualFree(ptr, 0, MEM_RELEASE);
#else
   // Invalid argument because no way this pointer was allocated by us
   throw Invalid_Argument("Invalid ptr to free_locked_pages");
#endif
   }

#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
namespace {

static ::sigjmp_buf g_sigill_jmp_buf;

void botan_sigill_handler(int)
   {
   ::siglongjmp(g_sigill_jmp_buf, /*non-zero return value*/1);
   }

}
#endif

int OS::run_cpu_instruction_probe(std::function<int ()> probe_fn)
   {
   volatile int probe_result = -3;

#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
   struct sigaction old_sigaction;
   struct sigaction sigaction;

   sigaction.sa_handler = botan_sigill_handler;
   sigemptyset(&sigaction.sa_mask);
   sigaction.sa_flags = 0;

   int rc = ::sigaction(SIGILL, &sigaction, &old_sigaction);

   if(rc != 0)
      throw Exception("run_cpu_instruction_probe sigaction failed");

   rc = ::sigsetjmp(g_sigill_jmp_buf, /*save sigs*/1);

   if(rc == 0)
      {
      // first call to sigsetjmp
      probe_result = probe_fn();
      }
   else if(rc == 1)
      {
      // non-local return from siglongjmp in signal handler: return error
      probe_result = -1;
      }

   // Restore old SIGILL handler, if any
   rc = ::sigaction(SIGILL, &old_sigaction, nullptr);
   if(rc != 0)
      throw Exception("run_cpu_instruction_probe sigaction restore failed");

#elif defined(BOTAN_TARGET_OS_IS_WINDOWS) && defined(BOTAN_TARGET_COMPILER_IS_MSVC)

   // Windows SEH
   __try
      {
      probe_result = probe_fn();
      }
   __except(::GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ?
            EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
      {
      probe_result = -1;
      }

#endif

   return probe_result;
   }

}
/*
* Various string utils and parsing functions
* (C) 1999-2007,2013,2014,2015 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <limits>

namespace Botan {

uint16_t to_uint16(const std::string& str)
   {
   const uint32_t x = to_u32bit(str);

   if(x >> 16)
      throw Invalid_Argument("Integer value exceeds 16 bit range");

   return static_cast<uint16_t>(x);
   }

uint32_t to_u32bit(const std::string& str)
   {
   // std::stoul is not strict enough. Ensure that str is digit only [0-9]*
   for(const char chr : str)
      {
      if(chr < '0' || chr > '9')
         {
         std::string chrAsString(1, chr);
         throw Invalid_Argument("String contains non-digit char: " + chrAsString);
         }
      }

   const unsigned long int x = std::stoul(str);

   if(sizeof(unsigned long int) > 4)
      {
      // x might be uint64
      if (x > std::numeric_limits<uint32_t>::max())
         {
         throw Invalid_Argument("Integer value of " + str + " exceeds 32 bit range");
         }
      }

   return static_cast<uint32_t>(x);
   }

/*
* Convert a string into a time duration
*/
uint32_t timespec_to_u32bit(const std::string& timespec)
   {
   if(timespec.empty())
      return 0;

   const char suffix = timespec[timespec.size()-1];
   std::string value = timespec.substr(0, timespec.size()-1);

   uint32_t scale = 1;

   if(Charset::is_digit(suffix))
      value += suffix;
   else if(suffix == 's')
      scale = 1;
   else if(suffix == 'm')
      scale = 60;
   else if(suffix == 'h')
      scale = 60 * 60;
   else if(suffix == 'd')
      scale = 24 * 60 * 60;
   else if(suffix == 'y')
      scale = 365 * 24 * 60 * 60;
   else
      throw Decoding_Error("timespec_to_u32bit: Bad input " + timespec);

   return scale * to_u32bit(value);
   }

/*
* Parse a SCAN-style algorithm name
*/
std::vector<std::string> parse_algorithm_name(const std::string& namex)
   {
   if(namex.find('(') == std::string::npos &&
      namex.find(')') == std::string::npos)
      return std::vector<std::string>(1, namex);

   std::string name = namex, substring;
   std::vector<std::string> elems;
   size_t level = 0;

   elems.push_back(name.substr(0, name.find('(')));
   name = name.substr(name.find('('));

   for(auto i = name.begin(); i != name.end(); ++i)
      {
      char c = *i;

      if(c == '(')
         ++level;
      if(c == ')')
         {
         if(level == 1 && i == name.end() - 1)
            {
            if(elems.size() == 1)
               elems.push_back(substring.substr(1));
            else
               elems.push_back(substring);
            return elems;
            }

         if(level == 0 || (level == 1 && i != name.end() - 1))
            throw Invalid_Algorithm_Name(namex);
         --level;
         }

      if(c == ',' && level == 1)
         {
         if(elems.size() == 1)
            elems.push_back(substring.substr(1));
         else
            elems.push_back(substring);
         substring.clear();
         }
      else
         substring += c;
      }

   if(!substring.empty())
      throw Invalid_Algorithm_Name(namex);

   return elems;
   }

std::vector<std::string> split_on(const std::string& str, char delim)
   {
   return split_on_pred(str, [delim](char c) { return c == delim; });
   }

std::vector<std::string> split_on_pred(const std::string& str,
                                       std::function<bool (char)> pred)
   {
   std::vector<std::string> elems;
   if(str.empty()) return elems;

   std::string substr;
   for(auto i = str.begin(); i != str.end(); ++i)
      {
      if(pred(*i))
         {
         if(!substr.empty())
            elems.push_back(substr);
         substr.clear();
         }
      else
         substr += *i;
      }

   if(substr.empty())
      throw Invalid_Argument("Unable to split string: " + str);
   elems.push_back(substr);

   return elems;
   }

/*
* Join a string
*/
std::string string_join(const std::vector<std::string>& strs, char delim)
   {
   std::string out = "";

   for(size_t i = 0; i != strs.size(); ++i)
      {
      if(i != 0)
         out += delim;
      out += strs[i];
      }

   return out;
   }

/*
* Parse an ASN.1 OID string
*/
std::vector<uint32_t> parse_asn1_oid(const std::string& oid)
   {
   std::string substring;
   std::vector<uint32_t> oid_elems;

   for(auto i = oid.begin(); i != oid.end(); ++i)
      {
      char c = *i;

      if(c == '.')
         {
         if(substring.empty())
            throw Invalid_OID(oid);
         oid_elems.push_back(to_u32bit(substring));
         substring.clear();
         }
      else
         substring += c;
      }

   if(substring.empty())
      throw Invalid_OID(oid);
   oid_elems.push_back(to_u32bit(substring));

   if(oid_elems.size() < 2)
      throw Invalid_OID(oid);

   return oid_elems;
   }

/*
* X.500 String Comparison
*/
bool x500_name_cmp(const std::string& name1, const std::string& name2)
   {
   auto p1 = name1.begin();
   auto p2 = name2.begin();

   while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
   while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

   while(p1 != name1.end() && p2 != name2.end())
      {
      if(Charset::is_space(*p1))
         {
         if(!Charset::is_space(*p2))
            return false;

         while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
         while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

         if(p1 == name1.end() && p2 == name2.end())
            return true;
         if(p1 == name1.end() || p2 == name2.end())
            return false;
         }

      if(!Charset::caseless_cmp(*p1, *p2))
         return false;
      ++p1;
      ++p2;
      }

   while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
   while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

   if((p1 != name1.end()) || (p2 != name2.end()))
      return false;
   return true;
   }

/*
* Convert a decimal-dotted string to binary IP
*/
uint32_t string_to_ipv4(const std::string& str)
   {
   std::vector<std::string> parts = split_on(str, '.');

   if(parts.size() != 4)
      throw Decoding_Error("Invalid IP string " + str);

   uint32_t ip = 0;

   for(auto part = parts.begin(); part != parts.end(); ++part)
      {
      uint32_t octet = to_u32bit(*part);

      if(octet > 255)
         throw Decoding_Error("Invalid IP string " + str);

      ip = (ip << 8) | (octet & 0xFF);
      }

   return ip;
   }

/*
* Convert an IP address to decimal-dotted string
*/
std::string ipv4_to_string(uint32_t ip)
   {
   std::string str;

   for(size_t i = 0; i != sizeof(ip); ++i)
      {
      if(i)
         str += ".";
      str += std::to_string(get_byte(i, ip));
      }

   return str;
   }

std::string erase_chars(const std::string& str, const std::set<char>& chars)
   {
   std::string out;

   for(auto c: str)
      if(chars.count(c) == 0)
         out += c;

   return out;
   }

std::string replace_chars(const std::string& str,
                          const std::set<char>& chars,
                          char to_char)
   {
   std::string out = str;

   for(size_t i = 0; i != out.size(); ++i)
      if(chars.count(out[i]))
         out[i] = to_char;

   return out;
   }

std::string replace_char(const std::string& str, char from_char, char to_char)
   {
   std::string out = str;

   for(size_t i = 0; i != out.size(); ++i)
      if(out[i] == from_char)
         out[i] = to_char;

   return out;
   }

bool host_wildcard_match(const std::string& issued, const std::string& host)
   {
   if(issued == host)
      {
      return true;
      }

   size_t stars = 0;
   for(char c : issued)
      {
      if(c == '*')
         stars += 1;
      }

   if(stars > 1)
      {
      return false;
      }

   // first try to match the base, then the left-most label
   // which can contain exactly one wildcard at any position
   if(issued.size() > 2)
      {
      size_t host_i = host.find('.');
      if(host_i == std::string::npos || host_i == host.size() - 1)
         {
         return false;
         }

      size_t issued_i = issued.find('.');
      if(issued_i == std::string::npos || issued_i == issued.size() - 1)
         {
         return false;
         }

      const std::string host_base = host.substr(host_i + 1);
      const std::string issued_base = issued.substr(issued_i + 1);

      // if anything but the left-most label doesn't equal,
      // we are already out here
      if(host_base != issued_base)
         {
         return false;
         }

      // compare the left-most labels
      std::string host_prefix = host.substr(0, host_i);

      if(host_prefix.empty())
         {
         return false;
         }

      const std::string issued_prefix = issued.substr(0, issued_i);

      // if split_on would work on strings with less than 2 items,
      // the if/else block would not be necessary
      if(issued_prefix == "*")
         {
         return true;
         }

      std::vector<std::string> p;

      if(issued_prefix[0] == '*')
         {
         p = std::vector<std::string>{"", issued_prefix.substr(1, issued_prefix.size())};
         }
      else if(issued_prefix[issued_prefix.size()-1] == '*')
         {
         p = std::vector<std::string>{issued_prefix.substr(0, issued_prefix.size() - 1), ""};
         }
      else
         {
         p = split_on(issued_prefix, '*');
         }

      if(p.size() != 2)
         {
         return false;
         }

      // match anything before and after the wildcard character
      const std::string first = p[0];
      const std::string last = p[1];

      if(host_prefix.substr(0, first.size()) == first)
         {
         host_prefix.erase(0, first.size());
         }

      // nothing to match anymore
      if(last.empty())
         {
         return true;
         }

      if(host_prefix.size() >= last.size() &&
            host_prefix.substr(host_prefix.size() - last.size(), last.size()) == last)
         {
         return true;
         }
      }

   return false;
   }
}
/*
* Simple config/test file reader
* (C) 2013,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

std::string clean_ws(const std::string& s)
   {
   const char* ws = " \t\n";
   auto start = s.find_first_not_of(ws);
   auto end = s.find_last_not_of(ws);

   if(start == std::string::npos)
      return "";

   if(end == std::string::npos)
      return s.substr(start, end);
   else
      return s.substr(start, start + end + 1);
   }

std::map<std::string, std::string> read_cfg(std::istream& is)
   {
   std::map<std::string, std::string> kv;
   size_t line = 0;

   while(is.good())
      {
      std::string s;

      std::getline(is, s);

      ++line;

      if(s.empty() || s[0] == '#')
         continue;

      s = clean_ws(s.substr(0, s.find('#')));

      if(s.empty())
         continue;

      auto eq = s.find("=");

      if(eq == std::string::npos || eq == 0 || eq == s.size() - 1)
         throw Exception("Bad read_cfg input '" + s + "' on line " + std::to_string(line));

      const std::string key = clean_ws(s.substr(0, eq));
      const std::string val = clean_ws(s.substr(eq + 1, std::string::npos));

      kv[key] = val;
      }

   return kv;
   }

}
/*
* Semaphore
* (C) 2013 Joel Low
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_OS_HAS_THREADS)

// Based on code by Pierre Gaston (http://p9as.blogspot.com/2012/06/c11-semaphores.html)

namespace Botan {

void Semaphore::release(size_t n)
   {
   for(size_t i = 0; i != n; ++i)
      {
      lock_guard_type<mutex_type> lock(m_mutex);

      if(m_value++ < 0)
         {
         ++m_wakeups;
         m_cond.notify_one();
         }
      }
   }

void Semaphore::acquire()
   {
   std::unique_lock<mutex_type> lock(m_mutex);
   if(m_value-- <= 0)
       {
       m_cond.wait(lock, [this] { return m_wakeups > 0; });
       --m_wakeups;
       }
   }

}

#endif
/*
* Version Information
* (C) 1999-2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
  These are intentionally compiled rather than inlined, so an
  application running against a shared library can test the true
  version they are running against.
*/

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

const char* short_version_cstr()
   {
   return STR(BOTAN_VERSION_MAJOR) "."
          STR(BOTAN_VERSION_MINOR) "."
          STR(BOTAN_VERSION_PATCH);
   }

const char* version_cstr()
   {

   /*
   It is intentional that this string is a compile-time constant;
   it makes it much easier to find in binaries.
   */

   return "Botan " STR(BOTAN_VERSION_MAJOR) "."
                   STR(BOTAN_VERSION_MINOR) "."
                   STR(BOTAN_VERSION_PATCH) " ("
#if defined(BOTAN_UNSAFE_FUZZER_MODE)
                   "UNSAFE FUZZER MODE BUILD "
#endif
                   BOTAN_VERSION_RELEASE_TYPE
#if (BOTAN_VERSION_DATESTAMP != 0)
                   ", dated " STR(BOTAN_VERSION_DATESTAMP)
#endif
                   ", revision " BOTAN_VERSION_VC_REVISION
                   ", distribution " BOTAN_DISTRIBUTION_INFO ")";
   }

#undef STR
#undef QUOTE

/*
* Return the version as a string
*/
std::string version_string()
   {
   return std::string(version_cstr());
   }

std::string short_version_string()
   {
   return std::string(short_version_cstr());
   }

uint32_t version_datestamp() { return BOTAN_VERSION_DATESTAMP; }

/*
* Return parts of the version as integers
*/
uint32_t version_major() { return BOTAN_VERSION_MAJOR; }
uint32_t version_minor() { return BOTAN_VERSION_MINOR; }
uint32_t version_patch() { return BOTAN_VERSION_PATCH; }

std::string runtime_version_check(uint32_t major,
                                  uint32_t minor,
                                  uint32_t patch)
   {
   std::ostringstream oss;

   if(major != version_major() || minor != version_minor() || patch != version_patch())
      {
      oss << "Warning: linked version (" << short_version_string() << ")"
          << " does not match version built against "
          << "(" << major << '.' << minor << '.' << patch << ")\n";
      }

   return oss.str();
   }

}
