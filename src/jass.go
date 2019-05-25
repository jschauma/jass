/*
 * Copyright (c) 2013, Twitter. Inc.
 * Copyright (c) 2015, Yahoo, Inc.
 *
 * Originally written by Jan Schaumann <jschauma@twitter.com> in April
 * 2013 in shell; re-written in Go in December 2013.
 *
 * Currently maintained by Jan Schaumann <jschauma@yahoo-inc.com>.
 *
 * This little program allows you to easily share secrets with other users
 * by way of ssh pubkeys.
 */

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"regexp"
	"runtime"
	"strings"
	"syscall"
)

/*

Set these two variables to match your use of LDAP for ssh keys, if any.
Note: jass works perfectly fine without the use of LDAP.

var LDAPFIELD = "SSHPubkey"
var LDAPSEARCH = "ldapsearch -LLLxh ldap.yourdomain.com -b dc=example,dc=com"

*/
var LDAPFIELD = ""
var LDAPSEARCH = ""

/* You can enable default URLs here, if you so choose. */
var GITHUB_URL = "https://api.github.com/users/<user>/keys"
var KEYKEEPER_URL = ""

var URLS = map[string]*KeyURL{
	"GitHub":    {GITHUB_URL, true},
	"KeyKeeper": {KEYKEEPER_URL, false},
}

/* You should not need to make any changes below this line. */

const EXIT_FAILURE = 1
const EXIT_SUCCESS = 0
const MAX_COLUMNS = 76

const OPENSSH_RSA_KEY_SUBSTRING = "ssh-rsa AAAAB3NzaC1"
const OPENSSH_DSS_KEY_SUBSTRING = "ssh-dss AAAAB3NzaC1"

const PROGNAME = "jass"
const VERSION = "5.3"

var ACTION = "encrypt"

var FILES []string
var KEY_FILES = map[string]bool{}
var PASSIN string

type KeyURL struct {
	Url     string
	Enabled bool
}

type SSHKey struct {
	Key         rsa.PublicKey
	Fingerprint string
}

type GitHubKeys struct {
	Id  int
	Key string
}

type KeyKeeperKeys struct {
	Result struct {
		Keys struct {
			Key []struct {
				Trust     string
				Content   string
				Sudo      string
				Type      string
				Validated string
				Api       string
			}
		}
		Status string
		User   string
	}
}

var GROUPS = map[string]bool{}

var PUBKEYS = map[string][]SSHKey{}

var RECIPIENTS = map[string][]string{}

var VERBOSITY int = 0

/*
 * Main
 */

func main() {
	getopts()
	varCheck()

	if ACTION == "encrypt" {
		encrypt()
	} else if ACTION == "decrypt" {
		decrypt()
	} else if ACTION == "list" {
		list()
	}
}

/*
 * Functions
 */

func argcheck(flag string, args []string, i int) {
	if len(args) <= (i + 1) {
		fail(fmt.Sprintf("'%v' needs an argument\n", flag))
	}
}

func bytesToKey(skey []byte, salt []byte) (key []byte, iv []byte) {
	verbose("Deriving key and IV from session key and salt...", 3)

	/* Per http://www.ict.griffith.edu.au/anthony/info/crypto/openssl.hints :
	 * For aes-256 the key size is 32:
	 *
	 * Hash0 = ''
	 * Hash1 = MD5(Hash0 + Password + Salt)
	 * Hash2 = MD5(Hash1 + Password + Salt)
	 * Hash3 = MD5(Hash2 + Password + Salt)
	 * Hash4 = MD5(Hash3 + Password + Salt)
	 * ...
	 *
	 * The hash is then split to generate the 'Key' and 'IV' needed to
	 * decrypt.
	 *
	 * Key = Hash1 + Hash2
	 * IV  = Hash3
	 */
	rounds := 3
	hashes := make([][]byte, rounds+1)
	var hash []byte
	hashes[0] = hash

	for i := 1; i <= rounds; i++ {
		md5sum := md5.New()
		md5sum.Write(hashes[i-1])
		md5sum.Write(skey)
		md5sum.Write(salt)

		hashes[i] = md5sum.Sum(nil)
	}

	key = append(hashes[1], hashes[2]...)
	iv = hashes[3]

	return
}

func convertPubkeys() {
	verbose("Converting pubkeys to PKCS8 format...", 1)

	for recipient, keys := range RECIPIENTS {
		verbose(fmt.Sprintf("Converting pubkeys for '%v' to PKCS8 format...", recipient), 2)
		for _, key := range keys {
			if len(key) > 1 {
				pubkey := sshToPubkey(key)
				if pubkey.Key.E > 0 {
					PUBKEYS[recipient] = append(PUBKEYS[recipient], pubkey)
				}
			}
		}
	}

	if len(PUBKEYS) < 1 {
		fail("No valid public keys found.\n")
	}
}

func decodeBase64(input string) (decoded []byte) {
	verbose("Decoding data...", 2)
	verbose(fmt.Sprintf("Decoding '%v'...", input), 3)

	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to decode input:\n%v\n%v\n",
			input, err)
	}
	return
}

func decrypt() {
	verbose("Decrypting...", 1)

	var keys []string
	for k, _ := range KEY_FILES {
		keys = append(keys, k)
	}
	privkey := getRSAKeyFromSSHFile(keys[0])
	privfp := getFingerPrint(privkey.PublicKey)

	message, all_skeys, _ := parseEncryptedInput()

	skey := identifyCorrectSessionKeyData(privfp, all_skeys)
	sessionKey := decryptSessionKey(skey, privkey)

	decryptMessage(decodeBase64(message), sessionKey)
}

func decryptMessage(msg []byte, skey []byte) {
	verbose("Decrypting message...", 2)

	/* The first 8 bytes are "Salted__", followed by 8 bytes of salt. */
	salt := msg[8:16]
	msg = msg[16:]

	/* Hack!  Older versions of jass(1) generated a session key with a
	 * trailing '\n', which we have to strip here.  Properly generated
	 * session keys (as this version provides) should _not_ have a '\n' as
	 * the last char.  An old session key would be 45 bytes (32 random
	 * bytes, base64-encoded => 44 bytes + one trailing '\n'), so trim that.
	 *
	 * Backwards compatibility is a bitch. */
	if len(skey) == 45 {
		skey = skey[:len(skey)-1]
	}

	key, iv := bytesToKey(skey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		fail(fmt.Sprintf("Unable to set up new cipher: %s\n", err))
	}

	if len(msg)%aes.BlockSize != 0 {
		fail("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(msg, msg)

	msg = unpadBuffer(msg)
	fmt.Printf("%v", string(msg))
}

func decryptSessionKey(skey []byte, privkey *rsa.PrivateKey) (session_key []byte) {
	verbose("Decrypting session key...", 2)

	session_key, err := rsa.DecryptPKCS1v15(rand.Reader, privkey, skey)
	if err != nil {
		fail("Unable to decrypt session key.\n")
	}

	return
}

func encodeVersionInfo() {
	/* This is really only useful for debugging purposes. */
	verbose("Encoding version info...", 2)
	uuencode("version", []byte(fmt.Sprintf("VERSION: %v\n", VERSION)))
}

func encrypt() {
	verbose("Encrypting...", 1)

	getPubkeys()
	convertPubkeys()

	skey := base64.StdEncoding.EncodeToString(getRandomBytes(32))
	encryptData(skey)
	encryptSessionKey(skey)

	encodeVersionInfo()
}

func encryptData(skey string) {
	verbose("Encrypting data...", 2)

	salt := getRandomBytes(8)
	output := []byte("Salted__")
	output = append(output, salt...)

	key, iv := bytesToKey([]byte(skey), salt)

	var c chan []byte = make(chan []byte)
	go readInputFiles(c)
	data := padBuffer(<-c)

	block, err := aes.NewCipher(key)
	if err != nil {
		fail(fmt.Sprintf("Unable to create new cipher: %v\n", err))
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(data, data)

	output = append(output, data...)
	uuencode("message", output)
}

func encryptSessionKey(skey string) {
	verbose("Encrypting session key...", 2)

	for recipient, pubkeys := range PUBKEYS {
		for _, key := range pubkeys {
			random := rand.Reader
			ciphertext, err := rsa.EncryptPKCS1v15(random, &key.Key, []byte(skey))
			if err != nil {
				fail(fmt.Sprintf("Unable to encrypt session key for %v-%v: %v\n",
					recipient, key.Fingerprint, err))
			}

			uuencode(fmt.Sprintf("%v-%v", recipient, key.Fingerprint), ciphertext)
		}
	}
}

/*
 * Expanding a group happens by way of supplementary groups (ie
 * /etc/group), primary group (/etc/passwd), and LDAP.  All members of the
 * groups are added to the list of RECIPIENTS.
 */
func expandGroup(group string) {
	verbose(fmt.Sprintf("Expanding group '%v'...", group), 2)

	members := expandSupplementaryGroup(group)
	members = append(members, expandPrimaryGroup(group)...)

	if len(LDAPSEARCH) > 1 {
		members = append(members, expandLDAPGroup(group)...)
	}

	for _, m := range members {
		if len(m) > 0 {
			RECIPIENTS[m] = make([]string, 0)
		}
	}
}

func expandLDAPGroup(group string) (members []string) {
	verbose(fmt.Sprintf("Expanding group '%v' from LDAP...", group), 3)

	if len(LDAPSEARCH) < 1 {
		return
	}

	ldapsearch := append(strings.Split(LDAPSEARCH, " "),
		fmt.Sprintf("cn=%v", group), "memberUid")
	groups := runCommand(ldapsearch, false)
	for _, line := range strings.Split(groups, "\n") {
		fields := strings.Split(line, "memberUid: ")
		if len(fields) == 2 {
			members = append(members, fields[1])
		}
	}
	return
}

func expandPrimaryGroup(group string) []string {
	verbose(fmt.Sprintf("Expanding group '%v' by primary group membership...", group), 3)

	cmd := []string{"awk", "-F:", fmt.Sprintf("/^%v:/ { print $3}", group), "/etc/group"}
	gid := runCommand(cmd, false)

	if len(gid) < 1 {
		var none []string
		return none
	}

	cmd = []string{"awk", "-v", fmt.Sprintf("gid=%v", gid), "-F:", "{ if ($4 == gid) { print $1; }}", "/etc/passwd"}
	output := runCommand(cmd, false)
	return strings.Split(output, "\n")
}

func expandSupplementaryGroup(group string) []string {
	verbose(fmt.Sprintf("Expanding group '%v' by supplementary group membership...", group), 3)

	cmd := []string{"awk", "-F:", fmt.Sprintf("/^%v:/ { print $NF}", group), "/etc/group"}
	output := runCommand(cmd, false)

	return strings.Split(output, ",")
}

func fail(msg string) {
	fmt.Fprintf(os.Stderr, msg)
	os.Exit(EXIT_FAILURE)
}

func getFingerPrint(pubkey rsa.PublicKey) (fp string) {
	verbose("Generating fingerprint for raw public key...", 4)

	/* The fingerprint of a public key is just the md5 of the raw
	 * data.  That is, we combine:
	 *
	 * [0 0 0 7]  -- length of next chunk
	 * "ssh-rsa"
	 * 4 bytes    -- length of next chunk
	 * the public key exponent
	 * 4 bytes    -- length of next chunk
	 * 0          -- first byte of modulus, since it's signed
	 * the public key modulus
	 */
	var b bytes.Buffer
	b.Write([]byte{0, 0, 0, 7})
	b.Write([]byte("ssh-rsa"))

	/* exponent */
	x := new(big.Int)
	x.SetString(fmt.Sprintf("%d", pubkey.E), 0)
	b.Write([]byte{0, 0, 0, byte(len(x.Bytes()))})
	b.Write(x.Bytes())

	/* modulus */
	tmpbuf := make([]byte, 0)
	mlen := len(pubkey.N.Bytes()) + 1
	x.SetString(fmt.Sprintf("%d", mlen), 0)
	xlen := len(x.Bytes())
	for i := 0; i < xlen; i++ {
		tmpbuf = append(tmpbuf, 0)
	}
	tmpbuf = append(tmpbuf, x.Bytes()...)

	/* append one zero byte to indicate signedness */
	tmpbuf = append(tmpbuf, 0)

	b.Write(tmpbuf)
	b.Write(pubkey.N.Bytes())

	fingerprint := md5.New()
	fingerprint.Write(b.Bytes())
	for i, b := range fmt.Sprintf("%x", fingerprint.Sum(nil)) {
		if i > 0 && i%2 == 0 {
			fp += ":"
		}
		fp += string(b)
	}
	return
}


func getPubkeyFromBlob(blob []byte) (pubkey SSHKey) {
	/* Based on:
	 * http://cpansearch.perl.org/src/MALLEN/Convert-SSH2-0.01/lib/Convert/SSH2.pm
	 * https://gist.github.com/mahmoudimus/1654254,
	 * http://golang.org/src/pkg/crypto/x509/x509.go
	 *
	 * See also: http://www.netmeister.org/blog/ssh2pkcs8.html
	 *
	 * The key format is base64 encoded tuples of:
	 * - four bytes representing the length of the next data field
	 * - the data field
	 *
	 * In practice, for an RSA key, we get:
	 * - four bytes [0 0 0 7]
	 * - the string "ssh-rsa" (7 bytes)
	 * - four bytes
	 * - the exponent
	 * - four bytes
	 * - the modulus
	 */

	const (
		keyTypeField = iota
		exponentField = iota
		modulusField = iota
	)


	var k rsa.PublicKey
	n := 0
	for len(blob) > 4 {
		dlen := binary.BigEndian.Uint32(blob[:4])

		chunklen := int(dlen) + 4
		if len(blob) < chunklen {
			fmt.Fprintf(os.Stderr, "Invalid data while trying to extract public key.\n")
			fmt.Fprintf(os.Stderr, "Maybe a corrupted key?\n")
			return
		}

		data := blob[4:chunklen]
		blob = blob[chunklen:]

		switch n {
		case keyTypeField:
			if ktype := fmt.Sprintf("%s", data); ktype != "ssh-rsa" {
				fmt.Fprintf(os.Stderr, "Unsupported key type (%v).\n", ktype)
				return
			}
		case exponentField:
			i := new(big.Int)
			i.SetString(fmt.Sprintf("0x%v", hex.EncodeToString(data)), 0)
			k.E = int(i.Int64())
		case modulusField:
			i := new(big.Int)
			/* The value in this field is signed, so the first
			 * byte should be 0, so we strip it. */
			i.SetString(fmt.Sprintf("0x%v", hex.EncodeToString(data[1:])), 0)
			k.N = i
		}
		n++
	}

	pubkey.Key = k
	pubkey.Fingerprint = getFingerPrint(k)
	return
}


/* Pubkeys are retrieved by first trying local files, then looking in
 * LDAP, then looking at any URLs.  First match wins: if we have local
 * keys, we do _not_ go and ask LDAP. */
func getPubkeys() {
	verbose("Identifying/retrieving ssh pubkeys...", 2)

	for group, _ := range GROUPS {
		expandGroup(group)
	}

	for recipient, _ := range RECIPIENTS {
		var keys []string

		/* If we specified a pubkey on the command-line, that file
		 * name becomes the "recipient", so skip it here. */
		if len(RECIPIENTS[recipient]) > 0 {
			continue
		}

		verbose(fmt.Sprintf("Trying to find local pubkeys for '%v'...", recipient), 2)
		usr, err := user.Lookup(recipient)
		if err == nil {
			authkeys := usr.HomeDir + "/.ssh/authorized_keys"
			content, err := ioutil.ReadFile(authkeys)
			if err == nil {
				keys = strings.Split(strings.TrimSpace(string(content)), "\n")
			} else {
				verbose(fmt.Sprintf("Can't read %v/.ssh/authorized_keys...", usr.HomeDir), 2)
			}
		} else {
			verbose(fmt.Sprintf("No such local user: %v...", recipient), 2)
		}

		if len(keys) < 1 {
			keys = append(keys, getPubkeysFromLDAP(recipient)...)
		}
		if len(keys) < 1 {
			keys = append(keys, getPubkeysFromURLs(recipient)...)
		}

		if len(keys) > 0 {
			RECIPIENTS[recipient] = keys
		}
	}
}

func getPubkeysFromLDAP(uname string) (tkeys []string) {
	var onekey string

	if len(LDAPSEARCH) < 1 {
		return
	}

	verbose(fmt.Sprintf("Trying to get ssh pubkeys for '%v' from LDAP...", uname), 3)

	ldapsearch := append(strings.Split(LDAPSEARCH, " "),
		fmt.Sprintf("uid=%v", uname), LDAPFIELD)
	ldapout := runCommand(ldapsearch, false)
	for _, line := range strings.Split(ldapout, "\n") {
		fields := strings.Split(line, fmt.Sprintf("%v:", LDAPFIELD))
		if len(fields) == 2 {
			if len(onekey) > 0 {
				verbose(fmt.Sprintf("Found key '%v'...", onekey), 4)
				tkeys = append(tkeys, onekey)
			}
			onekey = strings.Trim(fields[1], ": ")
		}
		if strings.HasPrefix(line, " ") {
			onekey += strings.Trim(line, " ")
		}
	}
	if len(onekey) > 0 {
		verbose(fmt.Sprintf("Found key '%v'...", onekey), 4)
		tkeys = append(tkeys, onekey)
	}

	/*
	 * Keys may be base64, in which case (we assume) it will not
	 * contain any spaces, otherwise required for a valid ssh key.
	 */
	var keys []string
	for _, k := range tkeys {
		if !strings.Contains(k, " ") {
			verbose("Decoding base64 encoded key...", 4)
			decoded := decodeBase64(k)
			if len(decoded) < 1 {
				verbose(fmt.Sprintf("Unable to decode key '%v'.\n", k), 4)
				continue
			}
			keys = append(keys, strings.Split(string(decoded), "\n")...)
		} else {
			keys = append(keys, k)
		}
	}

	return keys
}

func getPubkeysFromURLs(uname string) (keys []string) {
	verbose(fmt.Sprintf("Trying to get ssh pubkeys for '%v' from URLs...", uname), 3)

	gitHubApiToken := os.Getenv("GITHUB_API_TOKEN")

	client := new(http.Client)

	for site, keyurl := range URLS {
		if !keyurl.Enabled {
			continue
		}

		url := strings.Replace(keyurl.Url, "<user>", uname, -1)
		verbose(fmt.Sprintf("Trying to get ssh pubkeys for '%v' from %v (%v)...", uname, site, url), 3)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to create new request %v: %v\n", url, err)
			continue
		}
		req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml,application/json")

		if site == "GitHub" && len(gitHubApiToken) > 0 {
			usr, err := user.Current()
			if err != nil {
				fail(fmt.Sprintf("%v\n", err))
			}
			req.SetBasicAuth(usr.Username, gitHubApiToken)
		}


		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to GET %v: %v\n", url, err)
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to read http response: %v\n", err)
			continue
		}

		if site == "KeyKeeper" {
			keys = append(keys, parseKeyKeeperJson(body)...)
		} else if site == "GitHub" {
			keys = append(keys, parseGitHubApiJson(body)...)
		} else {
			fmt.Fprintf(os.Stderr, "Unknown URL type, trying to just read the data.\n")
			keys = append(keys, strings.Split(string(body), "\n")...)
		}
	}

	return
}

func getPrivkeyFromOpenSSHBlob(blob []byte) (key *rsa.PrivateKey) {
	verbose("Extracting RSA private key from 'OPENSSH PRIVATE KEY' blob...", 5)

	var dlen uint32
	key = new(rsa.PrivateKey)

	/* The decrypted private key data blob has the
	 * following format:
	 * - four bytes checkint1
	 * - four bytes checkint2
	 * - four bytes length
	 * - privkey1
	 * - four bytes length
	 * - comment1
	 * - padding
	 *
	 * There might be more privkey/comment pairs,
	 * but we only support a single key at the
	 * moment, so we don't care.  (That seems
	 * reasonable, given that OpenSSH doesn't
	 * support multiple keys as of 2019-05-24
	 * either.)
	 *
	 * The privkey itself consists of:
	 * - a pubkey
	 *   - four bytes [0 0 0 7]
	 *   - the string "ssh-rsa" (7 bytes)
	 *   - four bytes
	 *   - the exponent
	 *   - four bytes
	 *   - the modulus
	 * - a private exponent
	 * - an array of primes (iqmp, p, q)
	 */
	const (
		checkint1Field = iota
		checkint2Field = iota
		pubkeyTypeField = iota
		pubkeyModulusField = iota
		pubkeyExponentField = iota
		privkeyExponentField = iota
		privkeyPrimesIqmp= iota
		privkeyPrimesP= iota
		privkeyPrimesQ = iota
		privkeyComment = iota
	)

	n := 0
	var checkint1, checkint2 int

	pubkeyData := map[string][]byte{}
	for len(blob) > 0 && n <= privkeyComment {
		dlen = binary.BigEndian.Uint32(blob[:4])

		switch n {
		case checkint1Field:
			blob = blob[4:]
			checkint1 = int(dlen)
		case checkint2Field:
			blob = blob[4:]
			checkint2 = int(dlen)
			if (checkint1 != checkint2) {
				fail("Decryption of private keys field in OPENSSH PRIVATE KEY file failed.")
			}

		case pubkeyTypeField:
			pubkeyData["type"] = blob[:4+dlen]
			blob = blob[4+dlen:]
		case pubkeyModulusField:
			pubkeyData["modulus"] = blob[:4+dlen]
			blob = blob[4+dlen:]
		case pubkeyExponentField:
			pubkeyData["exponent"] = blob[:4+dlen]
			allData := []byte{}
			allData = append(allData, pubkeyData["type"]...)
			allData = append(allData, pubkeyData["exponent"]...)
			allData = append(allData, pubkeyData["modulus"]...)
			sshkey := getPubkeyFromBlob(allData)
			key.PublicKey = sshkey.Key
			blob = blob[4+dlen:]

		case privkeyExponentField:
			data := blob[:4+dlen]
			key.D = new(big.Int)
			key.D.SetBytes(data[4:])
			blob = blob[4+dlen:]
		case privkeyPrimesIqmp:
			/* skip */
			blob = blob[4+dlen:]
		case privkeyPrimesP:
			data := blob[4:dlen]
			key.Primes = make([]*big.Int, 2)
			key.Primes[0] = new(big.Int)
			key.Primes[0].SetBytes(data[1:])
			blob = blob[4+dlen:]
		case privkeyPrimesQ:
			data := blob[4:dlen]
			key.Primes[1] = new(big.Int)
			key.Primes[1].SetBytes(data[1:])
			blob = blob[4+dlen:]

		case privkeyComment:
			/* skip */
			blob = blob[4+dlen:]
		}
		n++
	}

	return
}

/* The OpenSSH Key Format is described here:
 * https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
 * https://coolaj86.com/articles/the-openssh-private-key-format/
 * https://github.com/openssh/openssh-portable/blob/master/sshkey.c#sshkey_parse_private2
 * ħttps://github.com/golang/crypto/blob/master/ssh/keys.go#parseOpenSSHPrivateKey
 */
func getRSAKeyFromOpenSSH(keyFile string, pemData []byte, block *pem.Block) (key *rsa.PrivateKey) {
	verbose(fmt.Sprintf("Extracting RSA key from 'OPENSSH PRIVATE KEY' format in '%s'...", keyFile), 4)

	authMagic := "openssh-key-v1"
	if len(block.Bytes) < len(authMagic) ||
		string(block.Bytes[:len(authMagic)]) != authMagic {
		fail("Corrupt OPENSSH PRIVATE KEY file.\n")
	}

	keyBytes := block.Bytes[len(authMagic)+1:]

	/* After the magic header, we get:
	 * - four bytes representing the length of the next data field
	 * - the cipher name
	 * - four bytes length
	 * - kdfname
	 * - four bytes length
	 * - kdfoptions
	 * - four bytes numkeys
	 * - numkeys pubkeys (which we ignore here)
	 * - blob of numkeys privkeys
	 */
	const (
		cipherField = iota
		kdfnameField = iota
		kdfoptionsField = iota
		numKeysField = iota
		privkeyField = iota
	)

	var dlen uint32
	n := 0
	for len(keyBytes) > 0 && n <= privkeyField {
		dlen = binary.BigEndian.Uint32(keyBytes[:4])
		keyBytes = keyBytes[4:]
		chunklen := int(dlen)
		if len(keyBytes) < chunklen {
			fail("Invalid data - maybe a corrupted OPENSSH PRIVATE KEY file?\n")
		}

		switch n {
		case cipherField:
			data := keyBytes[:dlen]
			keyBytes = keyBytes[dlen:]
			cipher := string(data)
			if cipher != "none" {
				msg := "I'm sorry, at this time I only support unencrypted OPENSSH PRIVATE KEY files.\n"
				msg += "You may choose to convert the file to PEM format, which I _can_ handle even if encrypted.\n"
				msg += fmt.Sprintf("To do that, run 'ssh-keygen -p -f %s -m PEM'.\n", keyFile)
				fail(msg)
			}

		case kdfnameField:
			data := keyBytes[:dlen]
			keyBytes = keyBytes[dlen:]
			/* Since we currently only handle unencrypted
			 * files, we can ignore this field.  Otherwise,
			 * this should be e.g., 'bcrypt'. */
			_ = string(data)
		case kdfoptionsField:
			data := keyBytes[:dlen]
			keyBytes = keyBytes[dlen:]
			/* Since we currently only handle unencrypted
			 * files, we can ignore this field.  Otherwise,
			 * this should be a 4 bytes salt length,
			 * followed by the salt, followed by the
			 * uint32 'rounds'. */
			_ = data
		case numKeysField:
			numKeys := dlen
			if numKeys > 1 {
				fail("I'm sorry. At this time, I can only handle a single private key in an OPENSSH PRIVATE KEY file.\n")
			}
			/* We don't care about the pubkeys here, so we
			 * can just discard them. */
			for i := uint32(0); i < numKeys; i++ {
				dlen = binary.BigEndian.Uint32(keyBytes[:4])
				keyBytes = keyBytes[4+dlen:]
			}
		case privkeyField:
			data := keyBytes[:dlen]
			keyBytes = keyBytes[dlen:]
			/* If we supported encrypted keys, we'd decrypt
			 * the blob here, then pass the decrypted bytes
			 * to this function. */
			key = getPrivkeyFromOpenSSHBlob(data)
		}
		n++
	}
	return
}

func getRSAKeyFromPEM(keyFile string, pemData []byte, block *pem.Block) (key *rsa.PrivateKey) {
	verbose(fmt.Sprintf("Extracting RSA key from PEM data in '%s'...", keyFile), 4)

	var err error
	keyBytes := block.Bytes
	if strings.Contains(string(pemData), "Proc-Type: 4,ENCRYPTED") {
		password := getpass(fmt.Sprintf("Enter pass phrase for %s: ", keyFile))
		keyBytes, err = x509.DecryptPEMBlock(block, password)
		if err != nil {
			fail(fmt.Sprintf("Unable to decrypt private key: %v\n", err))
		}
	}

	key, err = x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		fail(fmt.Sprintf("Unable to extract private key from PEM data: %v\n", err))
	}
	return
}

/* With help from:
 * https://stackoverflow.com/questions/14404757/how-to-encrypt-and-decrypt-plain-text-with-a-rsa-keys-in-go
 */
func getRSAKeyFromSSHFile(keyFile string) (key *rsa.PrivateKey) {
	verbose(fmt.Sprintf("Extracting RSA key from '%s'...", keyFile), 3)

	pemData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fail(fmt.Sprintf("Unable to read '%s'.\n", keyFile))
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		fail(fmt.Sprintf("Unable to PEM-decode '%s'.\n", keyFile))
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return getRSAKeyFromPEM(keyFile, pemData, block)
	case "OPENSSH PRIVATE KEY":
		return getRSAKeyFromOpenSSH(keyFile, pemData, block)
	default:
		fail(fmt.Sprintf("Unsupported key type %q.\n", block.Type))
	}

	return
}

func getRandomBytes(rlen int) (random_data []byte) {
	verbose("Generating random bytes...", 2)

	random_data = make([]byte, rlen)
	if _, err := rand.Read(random_data); err != nil {
		fail(fmt.Sprintf("%v\n", err))
	}

	return
}

func getopts() {
	eatit := false
	args := os.Args[1:]
	for i, arg := range args {
		if eatit {
			eatit = false
			continue
		}
		switch arg {
		case "-V":
			printVersion()
			os.Exit(EXIT_SUCCESS)
		case "-d":
			ACTION = "decrypt"
		case "-e":
			ACTION = "encrypt"
		case "-f":
			eatit = true
			argcheck("-f", args, i)
			f := args[i+1]
			if f == "-" {
				f = "/dev/stdin"
			}
			FILES = append(FILES, f)
		case "-g":
			eatit = true
			argcheck("-g", args, i)
			GROUPS[args[i+1]] = true
		case "-h":
			usage(os.Stdout)
			os.Exit(EXIT_SUCCESS)
		case "-k":
			eatit = true
			argcheck("-k", args, i)
			KEY_FILES[args[i+1]] = true
		case "-l":
			ACTION = "list"
		case "-p":
			eatit = true
			argcheck("-p", args, i)
			PASSIN = args[i+1]
		case "-u":
			eatit = true
			argcheck("-u", args, i)
			RECIPIENTS[args[i+1]] = make([]string, 0)
		case "-v":
			VERBOSITY++
		default:
			fmt.Fprintf(os.Stderr, "Unexpected option or argument: %v\n", args[i])
			usage(os.Stderr)
			os.Exit(EXIT_FAILURE)
		}
	}
}

func getpass(prompt string) (pass []byte) {
	verbose("Getting password...", 4)

	var source string
	var passin []string
	error_message := fmt.Sprintf("Invalid argument for passphrase: %v\n", PASSIN)
	if len(PASSIN) == 0 {
		source = "tty"
	} else {
		passin = strings.SplitN(PASSIN, ":", 2)
		if len(passin) < 2 {
			fmt.Fprintf(os.Stderr, error_message)
			os.Exit(EXIT_FAILURE)
		}
		source = passin[0]
	}

	switch source {
	case "tty":
		return getpassFromUser(prompt)
	case "pass":
		return []byte(passin[1])
	case "file":
		return getpassFromFile(passin[1])
	case "env":
		return getpassFromEnv(passin[1])
	default:
		fail(error_message)
	}

	return
}

func getpassFromEnv(varname string) (pass []byte) {
	pass = []byte(os.Getenv(varname))
	if len(pass) < 1 {
		fail(fmt.Sprintf("Environment variable '%v' not set.\n", varname))
	}
	return
}

func getpassFromFile(fname string) (pass []byte) {
	verbose(fmt.Sprintf("Getting password from file '%s'...", fname), 5)
	file, err := os.Open(fname)
	if err != nil {
		fail(fmt.Sprintf("Unable to open '%s': %v\n", fname, err))
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		return []byte(scanner.Text())
	}

	return
}

func getpassFromUser(prompt string) (pass []byte) {
	verbose("Getting password from user...", 5)

	dev_tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fail(fmt.Sprintf("%v\n", err))
	}

	fmt.Fprintf(dev_tty, prompt)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		stty("echo")
		os.Exit(EXIT_FAILURE)
	}()

	stty("-echo")

	input := bufio.NewReader(dev_tty)
	pass, err = input.ReadBytes('\n')
	if err != nil {
		fail(fmt.Sprintf("Unable to read data from user: %v\n", err))
	}

	stty("echo")
	fmt.Fprintf(dev_tty, "\n")

	return pass[:len(pass)-1]
}

func identifyCorrectSessionKeyData(privfp string, keys map[string]string) (skey []byte) {
	verbose("Identifying correct session key data...", 2)

	/* fingerprints may be "anything-fi:ng:er:pr:in:t" or "fi:ng:er:pr:in:t" */
	fp_pattern := regexp.MustCompile("^(.+-)?(?P<fp>[[:xdigit:]:]+)$")

	for r, key := range keys {
		fp := fp_pattern.FindStringSubmatch(r)[2]
		if fp == privfp {
			skey = decodeBase64(key)
			break
		}
	}

	if len(skey) < 1 {
		fail(fmt.Sprintf("Data was not encrypted for the key '%v'.\n", privfp))
	}

	return
}

func list() {
	verbose("Listing recipients from input...", 2)
	parseEncryptedInput()
}

func padBuffer(buf []byte) (padded []byte) {
	/* We will uses PKCS7 padding: The value of each added byte is the
	 * number of bytes that are added, i.e. N bytes, each of value N
	 * are added.
	 *
	 * We _always_ add padding, even if the input is already a
	 * blocksize-multiple.
	 */

	num := aes.BlockSize - len(buf)%aes.BlockSize

	padded = buf
	for i := 0; i < num; i++ {
		padded = append(padded, byte(num))
	}

	return
}

/* jass(1) input consists of at least three uuencoded components:
 * - the actual data, encrypted with a session key
 * - the session key encrypted for each recipient's public key
 * - a short version blob */
func parseEncryptedInput() (message string, keys map[string]string, version string) {
	verbose("Parsing encrypted input...", 2)

	begin_re := regexp.MustCompile("^begin-base64 600 (?P<name>[^ ]+)")
	end_re := regexp.MustCompile("^====")

	keys = make(map[string]string)

	/* There's only one file when decrypting. */
	file := FILES[0]

	verbose(fmt.Sprintf("Parsing data from %v...", file), 3)

	fd, err := os.Open(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}

	var field string
	var garbage string
	var encoded *string = &garbage
	var key string
	n := 0
	input := bufio.NewReader(fd)
	for {
		data, err := input.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Unable to read input: %v\n", err)
			}
			break
		}

		line := strings.TrimSpace(string(data))
		if begin_re.MatchString(line) {
			n++
			field = begin_re.FindStringSubmatch(line)[1]
			switch {
			case field == "message":
				encoded = &message
			case field == "version":
				encoded = &version
			default:
				if ACTION == "list" {
					fmt.Printf("%v\n", field)
				}
				encoded = &key
			}
		} else if end_re.MatchString(line) {
			if encoded == &key {
				keys[field] = *encoded
				key = ""
			}
			encoded = &garbage
			continue
		} else {
			*encoded += line
		}
	}
	fd.Close()

	if len(garbage) > 0 {
		fail("Garbage found in input. Aborting\n")
	}

	if len(message) < 1 || len(keys) < 1 {
		fail("No valid jass input found.\n")
	}

	return
}

func parseGitHubApiJson(data []byte) (keys []string) {
	verbose("Parsing GitHub API json...", 4)
	verbose(fmt.Sprintf("%v", string(data)), 5)

	var gkeys []GitHubKeys
	err := json.Unmarshal(data, &gkeys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse json: %v\n", err)
		fmt.Fprintf(os.Stderr, "%s\n", string(data))
		fmt.Fprintf(os.Stderr, "Maybe you need to set the GITHUB_API_TOKEN environment variable?\n")
		return
	}

	for _, k := range gkeys {
		keys = append(keys, k.Key)
	}

	return
}

func parseKeyKeeperJson(data []byte) (keys []string) {
	verbose("Parsing KeyKeeper json...", 4)
	verbose(fmt.Sprintf("%v", string(data)), 5)

	var kkeys KeyKeeperKeys
	err := json.Unmarshal(data, &kkeys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse json: %v\n", err)
		return
	}

	for _, k := range kkeys.Result.Keys.Key {
		keys = append(keys, k.Content)
	}

	return
}

func printVersion() {
	fmt.Printf("%v version %v\n", PROGNAME, VERSION)
}

func readInputFiles(c chan []byte) {
	verbose("Reading input from all files...", 2)

	alldata := make([]byte, 0)
	for _, file := range FILES {
		verbose(fmt.Sprintf("Encrypting data from %v...", file), 3)
		data, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			continue
		}

		alldata = append(alldata, data...)
	}
	c <- alldata
}

func runCommand(args []string, need_tty bool) string {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	verbose(fmt.Sprintf("Running: %v", strings.Join(args, " ")), 4)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if need_tty {
		dev_tty, err := os.Open("/dev/tty")
		if err != nil {
			fail(fmt.Sprintf("%v\n", err))
		}
		cmd.Stdin = dev_tty
	}
	err := cmd.Run()
	if err != nil {
		fail(fmt.Sprintf("Unable to run '%v':\n%v\n%v\n", strings.Join(args, " "), stderr.String(), err))
	}
	return strings.TrimSpace(stdout.String())
}

func runCommandStdinPipe(cmd *exec.Cmd) (pipe io.WriteCloser) {
	pipe, err := cmd.StdinPipe()
	if err != nil {
		fail(fmt.Sprintf("Unable to create pipe to command: %v\n", err))
	}
	err = cmd.Start()
	if err != nil {
		fail(fmt.Sprintf("Unable to run pipe to command: %v\n", err))
	}

	return
}

func sshToPubkey(key string) (pubkey SSHKey) {
	verbose("Converting SSH input into a public key...", 3)

	/* Many users have DSS keys stored in addition to RSA keys.  When
	 * multiple keys are used, having an error for what is a valid SSH
	 * key, just not of type RSA, is a bit annoying, so we silence
	 * this error by default. */
	i := strings.Index(key, OPENSSH_DSS_KEY_SUBSTRING)
	if i >= 0 {
		if VERBOSITY > 0 {
			fmt.Fprintf(os.Stderr, "Skipping what looks like a DSS key to me.\n")
		}
		if VERBOSITY > 1 {
			fmt.Fprintf(os.Stderr, key)
		}
		return
	}

	/* An RSA SSH key can have leading key options (including quoted
	 * whitespace) and trailing comments (including whitespace).  We
	 * take a short cut here and assume that if it contains the known
	 * RSA pattern, then that field must be the actual key.  This
	 * would be a false assumption if one of the comments or options
	 * contained that same pattern, but anybody who creates such a key
	 * can go screw themselves. */
	i = strings.Index(key, OPENSSH_RSA_KEY_SUBSTRING)
	if i < 0 {
		fmt.Fprintf(os.Stderr, "Not an ssh RSA public key: '%v'\n", key)
		return
	}

	fields := strings.Split(key[i:], " ")
	decoded := decodeBase64(fields[1])
	if len(decoded) < 1 {
		fmt.Fprintf(os.Stderr, "Unable to decode key.\n")
		return
	}

	pubkey = getPubkeyFromBlob(decoded)
	return
}

func stty(arg string) {

	flag := "-f"
	if runtime.GOOS == "linux" {
		flag = "-F"
	}

	err := exec.Command("/bin/stty", flag, "/dev/tty", arg).Run()
	if err != nil {
		fail(fmt.Sprintf("Unable to run stty on /dev/tty: %v\n", err))
	}
}

func unpadBuffer(buf []byte) (unpadded []byte) {
	/* OpenSSL (with which we're trying to be compatible) uses PKCS7
	 * padding: The value of each added byte is the number of bytes
	 * that are added, i.e. N bytes, each of value N are added.
	 *
	 * In other words, we can just check the value of the last byte
	 * and then strip off as many to unpad. */
	unpadded = buf
	last := unpadded[len(unpadded)-1]
	unpadded = unpadded[:len(unpadded)-int(last)]
	return
}

func usage(out io.Writer) {
	usage := `Usage: %v [-Vdehlv] [-f file] [-g group] [-k key] [-p passin] [-u user]
	-V        print version information and exit
	-d        decrypt
	-e        encrypt (default)
	-f file   Encrypt/decrypt file (default: stdin)
	-g group  encrypt for members of this group
	-h        print this help and exit
	-k key    encrypt using this public key file
	-l        list recipients
	-p passin pass:passphrase, env:envvar, file:filename
	-u user   encrypt for this user
	-v        be verbose
`
	fmt.Fprintf(out, usage, PROGNAME)
}

func uuencode(name string, msg []byte) {
	verbose(fmt.Sprintf("Uuencoding %v...", name), 3)

	/* Earlier versions of jass(1) used uuencode(1), so we mimic the
	 * same behaviour here for backwards compatibility. */
	fmt.Printf("begin-base64 600 %v\n", name)
	out := base64.StdEncoding.EncodeToString(msg)
	for len(out) > MAX_COLUMNS {
		fmt.Printf("%v\n", out[:MAX_COLUMNS])
		out = out[MAX_COLUMNS:]
	}
	fmt.Printf("%v\n", out)
	fmt.Printf("====\n")
}

func verbose(msg string, level int) {
	if level <= VERBOSITY {
		for i := 0; i < level; i++ {
			fmt.Fprintf(os.Stderr, "=")
		}
		fmt.Fprintf(os.Stderr, "> %v\n", msg)
	}
}

func varCheck() {
	verbose("Checking that all variables look ok...", 1)

	if len(FILES) < 1 {
		FILES = append(FILES, "/dev/stdin")
	}

	ldapfield := os.Getenv("LDAPFIELD")
	if len(ldapfield) > 1 {
		LDAPFIELD = ldapfield
	}

	ldapsearch := os.Getenv("LDAPSEARCH")
	if len(ldapsearch) > 1 {
		LDAPSEARCH = ldapsearch
	}

	keykeeper_url, found := os.LookupEnv("KEYKEEPER_URL")
	if len(keykeeper_url) > 1 {
		URLS["KeyKeeper"].Url = keykeeper_url
		URLS["KeyKeeper"].Enabled = true
	} else if found {
		URLS["KeyKeeper"].Enabled = false
	}

	github_url, found := os.LookupEnv("GITHUB_URL")
	if len(github_url) > 1 {
		if !strings.HasPrefix(github_url, "http://") &&
			!strings.HasPrefix(github_url, "https://") {
			github_url = "https://" + github_url
		}
		URLS["GitHub"].Url = github_url
		URLS["GitHub"].Enabled = true
	} else if found {
		URLS["GitHub"].Enabled = false
	}

	switch ACTION {
	case "decrypt":
		varCheckDecrypt()
	case "encrypt":
		varCheckEncrypt()
	case "list":
		varCheckList()
	}
}

func varCheckDecrypt() {
	verbose("Checking that all variables look ok for decrypting...", 2)
	if len(RECIPIENTS) != 0 || len(GROUPS) != 0 {
		fail("You cannot specify any recipients when decrypting.\n")
	}

	if len(FILES) == 0 {
		FILES = append(FILES, "/dev/stdin")
	} else if len(FILES) > 1 {
		fail("You can only decrypt one file at a time.\n")
	}

	if len(KEY_FILES) == 0 {
		verbose("No key specified, trying ~/.ssh/id_rsa...", 2)
		usr, err := user.Current()
		if err != nil {
			fail(fmt.Sprintf("%v\n", err))
		}
		privkey := usr.HomeDir + "/.ssh/id_rsa"
		KEY_FILES[privkey] = true
	} else if len(KEY_FILES) > 1 {
		fail("Please only specify a single key file when decrypting.\n")
	}

	var keys []string
	for k, _ := range KEY_FILES {
		keys = append(keys, k)
	}

	privkey, err := ioutil.ReadFile(keys[0])
	if err != nil {
		fail(fmt.Sprintf("%v\n", err))
	}

	if strings.Contains(string(privkey), OPENSSH_RSA_KEY_SUBSTRING) {
		fail(fmt.Sprintf("'%v' looks like a public key to me. Please specify a private key when decrypting.\n", keys[0]))
	}
}

func varCheckEncrypt() {
	verbose("Checking that all variables look ok for encrypting...", 2)
	if len(KEY_FILES) > 0 {
		for file, _ := range KEY_FILES {
			keys, err := ioutil.ReadFile(file)
			if err != nil {
				fail(fmt.Sprintf("Unable to read %v: %v\n", file, err))
			}
			var key_data []string
			for _, line := range strings.Split(string(keys), "\n") {
				if len(line) < 1 {
					continue
				}
				if strings.Contains(line, OPENSSH_RSA_KEY_SUBSTRING) {
					key_data = append(key_data, line)
				} else {
					verbose(fmt.Sprintf("Not a public ssh key, ignoring: '%v'\n", line), 3)
				}
			}
			RECIPIENTS[file] = key_data
		}
	} else if len(RECIPIENTS) == 0 && len(GROUPS) == 0 {
		fail("You need to provide either a key file, a group, or a username.\n")
	}
}

func varCheckList() {
	verbose("Checking that all variables look ok for listing...", 2)
	if len(RECIPIENTS) != 0 || len(GROUPS) != 0 {
		fail("You cannot specify any recipients when listing recipients.\n")
	}

	if len(KEY_FILES) > 0 {
		fail("You cannot specify any keys when listing recipients.\n")
	}
}
