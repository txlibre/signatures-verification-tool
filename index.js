const EdDSA = require('elliptic').eddsa
const ec = new EdDSA('ed25519')
const blake2b = require('blake2b')

const PK_LEN = 64
const ADDR_LEN = 40
const SIGNATURE_LEN = 128

const SUCCESS = '\nOK: Ethereum address signature and declaration signature are both valid\n'
const FAIL_NO_PARAM = '\nUSAGE: node index.js <TZL_pk> <ETH_addr> <ETH_addrSignature> <declarationSignature>\n'
const FAIL_INPUT = '\nERROR: some inputs are NOT CORRECT\n'
const FAIL_ETH = '\nERROR: Ethereum address signature is INVALID\n'
const FAIL_DECLARATION = '\nERROR: Declaration signature is INVALID\n'

const DECLARATION = 'I hereby cryptographically prove to be a contributor of Tezos Stiftung (CHE-290.597.458), a Swiss Foundation based in Gubelstrasse 11, 6300 Zug, Switzerland. I recognize and welcome the existence multiple implementations of Tezos. I ask and expect Tezos Stiftung to foster competition among them by funding and supporting their development, marketing and growth. Funds allotted to various Tezos implementations shall always be directly proportional to their market capitalization at the time of each distribution of funds. Distribution of funds to multiple existing Tezos implementations shall begin no later than January 1st 2019 and consistently continue throughout time. Following priorities autonomously set by each community, Tezos Stiftung shall distribute funds in the most appropriate, effective and transparent way.'

/**
 * remove_0x_prefix
 * Remove the 0x prefix
 *
 * @param {String} str
 * @return {String}
 */

function remove_0x_prefix (str) {
  if (str.startsWith('0x')) {
    return str.slice(2)
  }

  return str
}

/**
 * canonize_and_check
 * Remove 0x prefix and check length of the input.
 *
 * @param {String} input.
 * @param {Number} len
 * @return {String
 */

function canonize_and_check (input, len) {
  let canonized = remove_0x_prefix(input)
  let has_correct_length = canonized.length === len
  return has_correct_length ? canonized : ''
}


/**
 * hash
 * Compute 64 byte long Blake2b hash of a message.
 *
 * @param {String} msg // no 0x-prefixed
 * @param {String} enc ['hex'|'utf8'] // no 0x-prefixed
 * @return {Buffer}
 */

function hash (msg, enc) {
  let buf = Buffer.from(msg, enc)
  let hash = blake2b(64).update(buf).digest('hex')

  return Buffer.from(hash, 'hex')
}

/**
 * verify
 * Tezos signature verification on eth address.
 *
 * @param {String} signature // no 0x-prefixed
 * @param {String} msg // no 0x-prefixed
 * @param {String} tzl_pk // no 0x-prefixed
 * @return {Boolean}
 */

function verify (signature, msg, tzl_pk, enc) {
  // create key pair from public
  let key = ec.keyFromPublic(tzl_pk, 'hex')

  // generate message hash
  let msgHash = Buffer.from(hash(msg, enc))

  // verify and return
  return key.verify(msgHash, signature)
}

/** MAIN **/
async  function main () {
  let status_code = FAIL_NO_PARAM

  try {
    let argv = process.argv
    if (argv.length !== 6){
      console.log(status_code) // FAIL
      return
    }

    let tzl_pk = canonize_and_check(argv[2], PK_LEN)
    let eth_addr = canonize_and_check(argv[3], ADDR_LEN)
    let addr_signature = canonize_and_check(argv[4], SIGNATURE_LEN)
    let declaration_signature = canonize_and_check(argv[5], SIGNATURE_LEN)
    let has_input = !!tzl_pk && !!eth_addr && !!addr_signature && !! declaration_signature

    if (!has_input) {
      status_code = FAIL_INPUT
      console.log(status_code) // FAIL
      return
    }

    let valid_addr_signature = verify(addr_signature, eth_addr, tzl_pk, 'hex')

    if (!valid_addr_signature) {
      status_code = FAIL_ETH
      console.log(status_code) // FAIL
      return
    }

    let valid_declaration_signature = verify(declaration_signature, DECLARATION, tzl_pk, 'utf8')

    if (!valid_declaration_signature) {
      status_code = FAIL_DECLARATION
      console.log(status_code) // FAIL
      return
    }

    status_code = SUCCESS

    console.log(status_code)

  } catch (e) {
    console.log(status_code)
  }
}

if (typeof require !== undefined && require.main === module) {
  main().then().catch(err => console.log(e))
}
