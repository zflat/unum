// require ('thinbus-srp')
// import clientSessionFactory from 'thinbus-srp'


const BigInteger = require('jsbn').BigInteger;
const sha256 = require('js-sha256').sha256; // see also CryptoJS? https://stackoverflow.com/a/44817919
window.sha256 = sha256;
var CryptoJS = require("crypto-js");

  
// console.log(CryptoJS.enc.Hex.parse("86160"))
// console.log(CryptoJS.enc.Hex.parse("086160"))
// console.log(CryptoJS.enc.Hex.parse("0".repeat(253*2)+"086160"))
// var numWords = CryptoJS.enc.Hex.parse("0".repeat(253*2)+"086160");
// var hashVal = CryptoJS.SHA256(numWords);
// console.log(hashVal)
// console.log("CryptoJS val hashed: "+hashVal.toString(CryptoJS.enc.Hex));


/**
 * Create a zero padded byte array from the given hex value
 *
 * @param strHex      Hex representation of the value as a string
 * @param total_bytes The total size of the encoded byte array
 * @return Uint8Array Array of encode bytes
 */ 
var str2bytes = function(strHex, total_bytes) {
  if(strHex.length%2) {
    strHex = "0"+strHex // leading nibble
  }
  var n_bytes = strHex.length/2
  var leading_0s = total_bytes - n_bytes;
  var val = new Uint8Array(total_bytes);
  for(var i=leading_0s; i<total_bytes; i++) {
    var nth = (i-leading_0s)*2
    val[i] = parseInt(strHex.substring(nth, nth+2), 16)
  }
  return val
}

var rfc5054 = {
  N_base10: "21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819",
  g_base10: "2", 
  k_base16: "5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300"
}

// var intN = new BigInteger(rfc5054.N_base10, 10)
// var encoded_bytes = intN.bitLength()/8
// console.log('Total bytes to encode: '+encoded_bytes)
// console.log("H of zero padded val: "+sha256(str2bytes("86160", encoded_bytes)).toUpperCase())
// console.log("H of zero padded val: "+sha256(str2bytes("61", encoded_bytes)).toUpperCase())

// generate the client session class from the client session factory using the safe prime constants
const SRP6JavascriptClientSession = require('thinbus-srp/client.js')(rfc5054.N_base10, rfc5054.g_base10, rfc5054.k_base16);

// instantiate a client session
var client = new SRP6JavascriptClientSession();
// generate a random salt that should be stored with the user verifier
// const salt = client.generateRandomSalt(); 
const salt = "97e940aef61adb119e18ba14a92ea342fd8f79a89666e5e40ff144cfbeac52a3"; // hard coded for dev

const username = "person123";
const password = "pass123";

// generate the users password verifier that should be stored with their salt. 
const verifier = client.generateVerifier(salt, username, password);

// POST to host to register user
var reg = {
  username: username,
  salt: salt,
  verifier: verifier,
}
document.write(JSON.stringify(reg));
console.log(reg);


// Authentication

// client starts with the username and password. 
client = new SRP6JavascriptClientSession();
window.client = client
client.step1(username, password);

var run = function (BB) {
  // console.log("server B: "+BB )
  var credentials = client.step2(salt, BB);

  console.log(credentials);
  document.write(JSON.stringify(credentials));

  const clientSessionKey = client.getSessionKey(false);
  console.log("clientSessionKey:"+clientSessionKey);

  document.write(JSON.stringify({
    N: rfc5054.N_base10,
    g: rfc5054.g_base10,
    k: rfc5054.k_base16,
    k_10: client.fromHex(rfc5054.k_base16).toString(10),
    username: username,
    password: password,
    salt: salt,
    salt_10: client.fromHex(salt).toString(10),
    verifier: verifier,
    verifier_10: client.fromHex(verifier).toString(10),
    a: client.a.toString(16),
    a_10: client.a.toString(10),
    A:  client.A.toString(16),
    A_10:  client.A.toString(10),
    b: "E6EF737A1AEF514AE9D6620B2A6187F4A13058E3977E1D80AE2465588E24247C",
    b_10: client.fromHex("E6EF737A1AEF514AE9D6620B2A6187F4A13058E3977E1D80AE2465588E24247C").toString(10),
    B: BB,
    B_10: client.fromHex(BB).toString(10),
  }))

  return clientSessionKey;
}


console.log('client k: '+client.H(rfc5054.N_base10+rfc5054.g_base10))






















// client creates a password proof from the salt, challenge and the username and password provided at step1. this generates `A` the client public ephemeral number and `M1` the hash of `M1` of a shared session key derived from both `A` and `B`. You  post `A` and `M1` to the server (e.g. seperated by a colon) instead of a password. 
var BB = "601E7AB6ED616AF7D39B321B1CC292443C56E95251C4B9DF9DE184CA282B0E472A3AED8CD967ABFB283E70C111E896DC27AF30BAB805AAD71BB1F01C736B9D49B05C95F34E0067B13F2A6B1D252CFBF734395879B3ECB48FDCEF01F44B21D512071E6C6694A8DA0BA95077FCC5A551C64436528048B63A45C8534D8C072B03237AD14D18DE9F4FEB6577EE92941C7FA439FE8B96088867A88ACA6CB09FCE99738EF9A89AA48ABDD76363CD43B8FD3FC1EEF53870E47810649D9F382B4003A28A97C4826D03986B2C8BC86D46887C788FEF20A9BD4921C53A517590F72AE665CB553455BDBA3CC8DB522A62E49FC94B3E248321BF62227AA519D64F5F627B0D3C";

var AA = "3db24bf2c3968975f6e8692fa249a00d353feee7cdb50ed118aa0db048584d163bc4beda587221e49ac0f7e3fedb3acb06d308606d2a4211c22edcc746f964f5949aa075e7fa31a027a14a1320b0c2f6298402b968c0487622d90065269c4c6d3ad2a2a0f53e3df99a173651daa329401a44a123fd0a2ff8e987e9b66535ae56bee94b68d5bad37f2f9eb20492128cb0f85fe9320eff49c4264c00e16a87344a3bdaa6a7d594b9c73761448ceaafc92e6a5041ce6932c693489da093dd2d3bb3f3743ec90660040f9647a5856a90ee9d45ee62ab7c6eda90e21d10acb1dcfdf14e709c5df9bfc04a1e1367d091cb2c3fbcc342eb4941036f49ace4d0f551d510";

console.log(client.computeU(AA, BB).toString(16));


window.dorun = run;

run("A06C541E701B0CD1FF70D27526209AB1446B74E272A18E98B9B95543FA0623E1DABBF2C805F40D330ED86A469B1F1DEE235DCDE770B6B9271F460687BF5094DE11958882B9F48C0C164D3BC013E1C976B9C347D855172921AF4D0E852A822C543F862B7261410D81CBDD291AC551DBB5E235981CDDB49EA7CC4B66BA8202E375FBB8A8DF4F7514918204DB45194FCBE578A2CA141C45F7B54726EF6BBD50D3CD60570712409D7C0AE4D1491ED43859EA4B2613492E311620D5DDC0551D1CF0DBE28A13C4844BB17654F931B3C64F339461EA016FA2C9EB6A3F4CF014448DC21F0EEE3A95717856C6639A16A94A957A4CFA2D818C33E79AE3B6A479F7A8AA8136")
