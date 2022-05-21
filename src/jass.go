/*
 * Copyright (c) 2013, Twitter. Inc.
 * Copyright (c) 2015, Yahoo, Inc.
 *
 * Originally written by Jan Schaumann <jschauma@twitter.com> in April
 * 2013 in shell; re-written in Go in December 2013.
 *
 * Currently maintained by Jan Schaumann <jschauma@netmeister.org>.
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
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

	"golang.org/x/crypto/ssh"
)

/*

Set these two variables to match your use of LDAP for ssh keys, if any.
Note: jass works perfectly fine without the use of LDAP.

'<USER>' will be replaced with the username for whom
jass is trying to encrypt the data.

var LDAPFIELD = "SSHPubkey"
var LDAPSEARCH = "ldapsearch -LLLxh ldap.yourdomain.com -b dc=example,dc=com uid=<USER>"

These variables are here in case you want to hardcode
LDAP use into the tool; otherwise, simply set them as
environment variables.

*/
var LDAPFIELD = ""
var LDAPSEARCH = ""

/* You can enable default URLs here, if you so choose. */
var GITHUB_URL = "https://api.github.com"

var URLS = map[string]*KeyURL{
	"GitHub": {GITHUB_URL, true},
}

/* You should not need to make any changes below this line. */

const EXIT_FAILURE = 1
const EXIT_SUCCESS = 0
const MAX_COLUMNS = 76

const OPENSSH_RSA_KEY_SUBSTRING = "ssh-rsa AAAAB3NzaC1"
const OPENSSH_DSS_KEY_SUBSTRING = "ssh-dss AAAAB3NzaC1"

const PROGNAME = "jass"
const VERSION = "7.3"

var ACTION = "encrypt"

var CMD string
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
		fail("'%v' needs an argument", flag)
	}
}

func bytesToKey(skey []byte, salt []byte) (key []byte, iv []byte) {
	verbose(3, "Deriving key and IV from session key and salt...")

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
	verbose(1, "Converting pubkeys to PKCS8 format...")

	for recipient, keys := range RECIPIENTS {
		verbose(2, "Converting pubkeys for '%v' to PKCS8 format...", recipient)
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
		fail("No valid public keys found.")
	}
}

func decodeBase64(input string) (decoded []byte) {
	verbose(2, "Decoding data...")
	verbose(3, "Decoding '%v'...", input)

	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to decode input:\n%v\n%v\n",
			input, err)
	}
	return
}

func decrypt() {
	verbose(1, "Decrypting...")

	var keys []string
	for k, _ := range KEY_FILES {
		keys = append(keys, k)
	}
	privkey := getRSAKeyFromSSHFile(keys[0])
	privfp := getFingerPrint(privkey.PublicKey)

	message, hmac, all_skeys, _ := parseEncryptedInput()

	skey := identifyCorrectSessionKeyData(privfp, all_skeys)
	sessionKey := decryptSessionKey(skey, privkey)

	if len(hmac) > 0 {
		verifyHMAC(sessionKey, decodeBase64(message), decodeBase64(hmac))
	} else {
		fmt.Fprintf(os.Stderr, "WARNING: missing HMAC!\n")
		_, unsafe := os.LookupEnv("JASS_NO_HMAC")
		if !unsafe {
			fail("\nOlder versions of jass(1) did not use an HMAC to verify\n" +
				"message integrity and authenticity.  As a result, the\n" +
				"data you're decrypting now might have been tampered\n" +
				"with.  If you still want me to decrypt the content, please\n" +
				"set the environment variable JASS_NO_HMAC and re-run\n" +
				"the command at your own risk.")
		}
	}
	decryptMessage(decodeBase64(message), sessionKey)
}

func decryptMessage(msg []byte, skey []byte) {
	verbose(2, "Decrypting message...")

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
		fail("Unable to set up new cipher: %s", err)
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
	verbose(2, "Decrypting session key...")

	session_key, err := rsa.DecryptPKCS1v15(rand.Reader, privkey, skey)
	if err != nil {
		fail("Unable to decrypt session key.")
	}

	return
}

func encodeVersionInfo() {
	/* This is really only useful for debugging purposes. */
	verbose(2, "Encoding version info...")
	uuencode("version", []byte(fmt.Sprintf("VERSION: %v\n", VERSION)))
}

func encrypt() {
	verbose(1, "Encrypting...")

	getPubkeys()
	convertPubkeys()

	skey := base64.StdEncoding.EncodeToString(getRandomBytes(32))
	encryptData(skey)
	encryptSessionKey(skey)

	encodeVersionInfo()
}

func encryptData(skey string) {
	verbose(2, "Encrypting data...")

	salt := getRandomBytes(8)
	output := []byte("Salted__")
	output = append(output, salt...)

	key, iv := bytesToKey([]byte(skey), salt)

	var c chan []byte = make(chan []byte)
	go readInputFiles(c)
	data := padBuffer(<-c)

	block, err := aes.NewCipher(key)
	if err != nil {
		fail("Unable to create new cipher: %v", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(data, data)

	output = append(output, data...)
	uuencode("message", output)
	generateHMAC(skey, output)
}

func encryptSessionKey(skey string) {
	verbose(2, "Encrypting session key...")

	for recipient, pubkeys := range PUBKEYS {
		for _, key := range pubkeys {
			random := rand.Reader
			ciphertext, err := rsa.EncryptPKCS1v15(random, &key.Key, []byte(skey))
			if err != nil {
				fail("Unable to encrypt session key for %v-%v: %v",
					recipient, key.Fingerprint, err)
			}

			uuencode(fmt.Sprintf("%v-%v", recipient, key.Fingerprint), ciphertext)
		}
	}
}

func expandGitHubTeam(githubTeam string) (members []string) {
	verbose(2, "Expanding GitHub team '%v'...", githubTeam)

	id := githubTeam

	numeric_re := regexp.MustCompile(`^[0-9]+$`)
	if !numeric_re.MatchString(githubTeam) {
		orgTeam_re := regexp.MustCompile(`^(.*)/(.*)$`)
		m := orgTeam_re.FindStringSubmatch(githubTeam)
		if len(m) < 1 {
			fmt.Fprintf(os.Stderr, "Not trying to resolve '%s' - which is neither a numeric team name nor in the format 'org/team' - as a GitHub Team.", githubTeam)
			return
		}

		org := m[1]
		team := m[2]
		url := fmt.Sprintf("%s/orgs/%s/teams/%s", URLS["GitHub"].Url, org, team)
		data := getURLContents("GitHub", url)

		type GitHubTeamInfo struct {
			Message string
			Id      int
		}

		var teamInfo GitHubTeamInfo
		err := json.Unmarshal(data, &teamInfo)
		if err != nil {
			printGitHubApiError(data)
			return
		}
		if len(teamInfo.Message) > 0 {
			fmt.Fprintf(os.Stderr, "Unable to fetch team details for '%s': %s\n", githubTeam, teamInfo.Message)
			return
		}
		id = fmt.Sprintf("%d", teamInfo.Id)
	}

	url := fmt.Sprintf("%s/teams/%s/members", URLS["GitHub"].Url, id)
	data := getURLContents("GitHub", url)

	type GitHubUserInfo struct {
		Login string
	}

	var teamMembers []GitHubUserInfo
	err := json.Unmarshal(data, &teamMembers)
	if err != nil {
		printGitHubApiError(data)
		return
	}

	for _, m := range teamMembers {
		members = append(members, m.Login)
	}

	verbose(3, "Found %d GitHub team members...", len(members))
	return
}

/*
 * Expanding a group happens by way of supplementary groups (ie
 * /etc/group), primary group (/etc/passwd), LDAP, and GitHub teams.
 * All members of the groups are added to the list of RECIPIENTS.
 */
func expandGroup(group string) {
	verbose(2, "Expanding group '%v'...", group)

	var members []string

	/* GitHub teams may be "org/team", but we do
	 * not allow '/' in local group names. */
	if !strings.Contains(group, "/") {
		members = expandSupplementaryGroup(group)
		members = append(members, expandPrimaryGroup(group)...)
	}

	if len(LDAPSEARCH) > 0 {
		members = append(members, expandLDAPGroup(group)...)
	}

	if len(GITHUB_URL) > 0 {
		members = append(members, expandGitHubTeam(group)...)
	}

	for _, m := range members {
		if len(m) > 0 {
			RECIPIENTS[m] = make([]string, 0)
		}
	}
}

func expandLDAPGroup(group string) (members []string) {
	verbose(3, "Expanding group '%v' from LDAP...", group)

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
	verbose(3, "Expanding group '%v' by primary group membership...", group)

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
	verbose(3, "Expanding group '%v' by supplementary group membership...", group)

	cmd := []string{"awk", "-F:", fmt.Sprintf("/^%v:/ { print $NF}", group), "/etc/group"}
	output := runCommand(cmd, false)

	return strings.Split(output, ",")
}

func fail(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
	os.Exit(EXIT_FAILURE)
}

func generateHMAC(skey string, data []byte) {
	verbose(2, "Generating HMAC...")

	h := hmac.New(sha256.New, []byte(skey))
	h.Write(data)
	uuencode("hmac", h.Sum(nil))
}

func getFingerPrint(pubkey rsa.PublicKey) (fp string) {
	verbose(4, "Generating fingerprint for raw public key...")

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
		keyTypeField  = iota
		exponentField = iota
		modulusField  = iota
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
	verbose(2, "Identifying/retrieving ssh pubkeys...")

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

		verbose(2, "Trying to find local pubkeys for '%v'...", recipient)
		usr, err := user.Lookup(recipient)
		if err == nil {
			authkeys := usr.HomeDir + "/.ssh/authorized_keys"
			content, err := ioutil.ReadFile(authkeys)
			if err == nil {
				keys = strings.Split(strings.TrimSpace(string(content)), "\n")
			} else {
				verbose(2, "Can't read %v/.ssh/authorized_keys...", usr.HomeDir)
			}
		} else {
			verbose(2, "No such local user: %v...", recipient)
		}

		if len(keys) < 1 {
			keys = append(keys, getPubkeysCommand(recipient)...)
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

func getPubkeysCommand(uname string) (keys []string) {
	if len(CMD) < 1 {
		return
	}

	verbose(3, "Trying to get ssh pubkeys by running '%s %s'...", CMD, uname)

	cmd := []string{CMD, uname}
	results := runCommand(cmd, false)
	keys = append(keys, strings.Split(string(results), "\n")...)
	return
}

func getPubkeysFromLDAP(uname string) (keys []string) {
	var onekey string
	tkeys := []string{}

	if len(LDAPSEARCH) < 1 {
		return
	}

	verbose(3, "Trying to get ssh pubkeys for '%v' from LDAP...", uname)

	lds := strings.ReplaceAll(LDAPSEARCH, "<USER>", uname)

	ldapsearch := append(strings.Split(lds, " "), LDAPFIELD)
	ldapout := runCommand(ldapsearch, false)
	for _, line := range strings.Split(ldapout, "\n") {
		fields := strings.Split(line, fmt.Sprintf("%v:", LDAPFIELD))
		if len(fields) == 2 {
			if len(onekey) > 0 {
				verbose(4, "Found key '%v'...", onekey)
				tkeys = append(tkeys, onekey)
			}
			onekey = strings.Trim(fields[1], ": ")
		}
		if strings.HasPrefix(line, " ") {
			onekey += strings.Trim(line, " ")
		}
	}
	if len(onekey) > 0 {
		verbose(4, "Found key '%v'...", onekey)
		tkeys = append(tkeys, onekey)
	}

	/*
	 * Keys may be base64, in which case (we assume) it will not
	 * contain any spaces, otherwise required for a valid ssh key.
	 */
	for _, k := range tkeys {
		if !strings.Contains(k, " ") {
			verbose(4, "Decoding base64 encoded key...")
			decoded := decodeBase64(k)
			if len(decoded) < 1 {
				verbose(4, "Unable to decode key '%v'.", k)
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
	verbose(3, "Trying to get ssh pubkeys for '%v' from URLs...", uname)

	for site, keyurl := range URLS {
		if !keyurl.Enabled {
			continue
		}

		url := keyurl.Url
		if site == "GitHub" {
			url += "/users/<user>/keys"
		}

		url = strings.Replace(url, "<user>", uname, -1)
		results := getURLContents(site, url)

		if site == "GitHub" {
			keys = append(keys, parseKeysFromGitHubApiJson(results)...)
		} else {
			fmt.Fprintf(os.Stderr, "Unknown URL type, trying to just read the data.\n")
			keys = append(keys, strings.Split(string(results), "\n")...)
		}
	}

	return
}

func getRSAKeyFromSSHFile(keyFile string) (key *rsa.PrivateKey) {
	verbose(3, "Extracting RSA key from '%s'...", keyFile)

	pemData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fail("Unable to read '%s'.", keyFile)
	}

	rk, err := ssh.ParseRawPrivateKey(pemData)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			pass := getpass(fmt.Sprintf("Enter pass phrase for %s: ", keyFile))
			rk, err = ssh.ParseRawPrivateKeyWithPassphrase(pemData, pass)
			if err != nil {
				fail("unable to parse private key: %v", err)
			}
		} else {
			fail("unable to parse private key: %v", err)
		}
	}

	key = rk.(*rsa.PrivateKey)
	return
}

func getRandomBytes(rlen int) (random_data []byte) {
	verbose(2, "Generating random bytes...")

	random_data = make([]byte, rlen)
	if _, err := rand.Read(random_data); err != nil {
		fail("%v", err)
	}

	return
}

func getURLContents(site, url string) (data []byte) {
	verbose(4, "Fetching '%s'...", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create new request %v: %v\n", url, err)
		return
	}
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml,application/json")

	gitHubApiToken := os.Getenv("GITHUB_API_TOKEN")
	if site == "GitHub" && len(gitHubApiToken) > 0 {
		usr, err := user.Current()
		if err != nil {
			fail("%v", err)
		}
		req.SetBasicAuth(usr.Username, gitHubApiToken)
	}

	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to GET %v: %v\n", url, err)
		return
	}
	data, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read http response: %v\n", err)
		return
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
		case "-c":
			eatit = true
			argcheck("-c", args, i)
			CMD = args[i+1]
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
	verbose(4, "Getting password...")

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
	case "env":
		return getpassFromEnv(passin[1])
	case "file":
		return getpassFromFile(passin[1])
	case "keychain":
		return getpassFromKeychain(passin[1])
	case "lastpass":
		fallthrough
	case "lpass":
		return getpassFromLastpass(passin[1])
	case "onepass":
		fallthrough
	case "op":
		return getpassFromOnepass(passin[1])
	case "pass":
		return []byte(passin[1])
	case "tty":
		return getpassFromUser(prompt)
	default:
		fail(error_message)
	}

	return
}

func getpassFromEnv(varname string) (pass []byte) {
	pass = []byte(os.Getenv(varname))
	if len(pass) < 1 {
		fail("Environment variable '%v' not set.", varname)
	}
	return
}

func getpassFromFile(fname string) (pass []byte) {
	verbose(5, "Getting password from file '%s'...", fname)
	file, err := os.Open(fname)
	if err != nil {
		fail("Unable to open '%s': %v", fname, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		return []byte(scanner.Text())
	}

	return
}

func getpassFromKeychain(entry string) (pass []byte) {
	verbose(5, "Getting password from keychain entry '%s'...", entry)
	cmd := []string{"security", "find-generic-password", "-s", entry, "-w"}
	out := runCommand(cmd, false)
	return []byte(out)
}

func getpassFromLastpass(entry string) (pass []byte) {
	verbose(5, "Getting password from LastPass 'lpass' entry '%s'...", entry)
	cmd := []string{"lpass", "show", entry, "--password"}
	out := runCommand(cmd, false)
	return []byte(out)
}

func getpassFromOnepass(entry string) (pass []byte) {
	verbose(5, "Getting password from 1Password 'op' entry '%s'...", entry)
	cmd := []string{"op", "item", "get", entry, "--fields", "password"}
	out := runCommand(cmd, false)
	return []byte(out)
}

func getpassFromUser(prompt string) (pass []byte) {
	verbose(5, "Getting password from user...")

	dev_tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fail("%v", err)
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
		fail("Unable to read data from user: %v", err)
	}

	stty("echo")
	fmt.Fprintf(dev_tty, "\n")

	return pass[:len(pass)-1]
}

func identifyCorrectSessionKeyData(privfp string, keys map[string]string) (skey []byte) {
	verbose(2, "Identifying correct session key data...")

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
		fail("Data was not encrypted for the key '%v'.", privfp)
	}

	return
}

func list() {
	verbose(2, "Listing recipients from input...")
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
 * - the hmac, using the same session key
 * - the session key encrypted for each recipient's public key
 * - a short version blob */
func parseEncryptedInput() (message string, hmac string, keys map[string]string, version string) {
	verbose(2, "Parsing encrypted input...")

	begin_re := regexp.MustCompile("^begin-base64 600 (?P<name>[^ ]+)")
	end_re := regexp.MustCompile("^====")

	keys = make(map[string]string)

	/* There's only one file when decrypting. */
	file := FILES[0]

	verbose(3, "Parsing data from %v...", file)

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
			case field == "hmac":
				encoded = &hmac
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
		fail("Garbage found in input. Aborting.")
	}

	if len(message) < 1 || len(keys) < 1 {
		fail("No valid jass input found.")
	}

	return
}

func parseKeysFromGitHubApiJson(data []byte) (keys []string) {
	verbose(4, "Parsing GitHub API json...")
	verbose(5, string(data))

	type GitHubKeys struct {
		Id  int
		Key string
	}

	var gkeys []GitHubKeys
	err := json.Unmarshal(data, &gkeys)
	if err != nil {
		printGitHubApiError(data)
		return
	}

	for _, k := range gkeys {
		keys = append(keys, k.Key)
	}

	return
}

func printGitHubApiError(data []byte) {
	var errMsg map[string]string
	err := json.Unmarshal(data, &errMsg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse json: %v\n", err)
		fmt.Fprintf(os.Stderr, "%s\n", string(data))
		fmt.Fprintf(os.Stderr, "Maybe you need to set the GITHUB_API_TOKEN environment variable?\n")
	} else {
		/* Any message suggests an error, e.g. no such user. */
		if m, found := errMsg["message"]; found {
			fmt.Fprintf(os.Stderr, "here: %s\n", m)
		} else {
			fmt.Fprintf(os.Stderr, "Unexpected json results:\n%s\n", string(data))
		}
	}
}

func printVersion() {
	fmt.Printf("%v version %v\n", PROGNAME, VERSION)
}

func readInputFiles(c chan []byte) {
	verbose(2, "Reading input from all files...")

	alldata := make([]byte, 0)
	for _, file := range FILES {
		verbose(3, "Encrypting data from %v...", file)
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

	verbose(4, "Running: %v", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if need_tty {
		dev_tty, err := os.Open("/dev/tty")
		if err != nil {
			fail("%v", err)
		}
		cmd.Stdin = dev_tty
	}
	err := cmd.Run()
	if err != nil {
		fail("Unable to run '%v':\n%v\n%v", strings.Join(args, " "), stderr.String(), err)
	}
	return strings.TrimSpace(stdout.String())
}

func runCommandStdinPipe(cmd *exec.Cmd) (pipe io.WriteCloser) {
	pipe, err := cmd.StdinPipe()
	if err != nil {
		fail("Unable to create pipe to command: %v", err)
	}
	err = cmd.Start()
	if err != nil {
		fail("Unable to run pipe to command: %v", err)
	}

	return
}

func sshToPubkey(key string) (pubkey SSHKey) {
	verbose(3, "Converting SSH input into a public key...")

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
		fail("Unable to run stty on /dev/tty: %v", err)
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
	usage := `Usage: %v [-Vdehlv] [-c cmd] [-f file] [-g group] [-k key] [-p passin] [-u user]
	-V        print version information and exit
	-c cmd    use this command to fetch pubkeys
	-d        decrypt
	-e        encrypt (default)
	-f file   Encrypt/decrypt file (default: stdin)
	-g group  encrypt for members of this group
	-h        print this help and exit
	-k key    encrypt using this public key file
	-l        list recipients
	-p passin env:envvar, file:filename, keychain:name, pass:passphrase
	-u user   encrypt for this user
	-v        be verbose
`
	fmt.Fprintf(out, usage, PROGNAME)
}

func uuencode(name string, msg []byte) {
	verbose(3, "Uuencoding %v...", name)

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

func varCheck() {
	verbose(1, "Checking that all variables look ok...")

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
	verbose(2, "Checking that all variables look ok for decrypting...")
	if len(RECIPIENTS) != 0 || len(GROUPS) != 0 {
		fail("You cannot specify any recipients when decrypting.")
	}

	if len(CMD) > 0 {
		fail("'-c' only makes sense when encrypting.")
	}

	if len(FILES) == 0 {
		FILES = append(FILES, "/dev/stdin")
	} else if len(FILES) > 1 {
		fail("You can only decrypt one file at a time.")
	}

	if len(KEY_FILES) == 0 {
		verbose(2, "No key specified, trying ~/.ssh/id_rsa...")
		usr, err := user.Current()
		if err != nil {
			fail("%v", err)
		}
		privkey := usr.HomeDir + "/.ssh/id_rsa"
		KEY_FILES[privkey] = true
	} else if len(KEY_FILES) > 1 {
		fail("Please only specify a single key file when decrypting.")
	}

	var keys []string
	for k, _ := range KEY_FILES {
		keys = append(keys, k)
	}

	privkey, err := ioutil.ReadFile(keys[0])
	if err != nil {
		fail("%v", err)
	}

	if strings.Contains(string(privkey), OPENSSH_RSA_KEY_SUBSTRING) {
		fail("'%v' looks like a public key to me. Please specify a private key when decrypting.", keys[0])
	}
}

func varCheckEncrypt() {
	verbose(2, "Checking that all variables look ok for encrypting...")
	if len(KEY_FILES) > 0 {
		if len(CMD) > 0 {
			fail("'-c' conflicts with '-k'.")
		}

		for file, _ := range KEY_FILES {
			keys, err := ioutil.ReadFile(file)
			if err != nil {
				fail("Unable to read %v: %v", file, err)
			}
			var key_data []string
			for _, line := range strings.Split(string(keys), "\n") {
				if len(line) < 1 {
					continue
				}
				if strings.Contains(line, OPENSSH_RSA_KEY_SUBSTRING) {
					key_data = append(key_data, line)
				} else {
					verbose(3, "Not a public RSA ssh key, ignoring: '%v'\n", line)
				}
			}
			RECIPIENTS[file] = key_data
		}
	} else if len(RECIPIENTS) == 0 && len(GROUPS) == 0 {
		fail("You need to provide either a key file, a group, or a username.")
	}
}

func varCheckList() {
	verbose(2, "Checking that all variables look ok for listing...")
	if len(RECIPIENTS) != 0 || len(GROUPS) != 0 {
		fail("You cannot specify any recipients when listing recipients.")
	}

	if len(CMD) > 0 {
		fail("'-c' only makes sense when encrypting.")
	}

	if len(KEY_FILES) > 0 {
		fail("You cannot specify any keys when listing recipients.")
	}
}

func verbose(level int, format string, v ...interface{}) {
	if level <= VERBOSITY {
		for i := 0; i < level; i++ {
			fmt.Fprintf(os.Stderr, "=")
		}
		fmt.Fprintf(os.Stderr, "> "+format+"\n", v...)
	}
}

func verifyHMAC(key, message, givenHMAC []byte) {
	verbose(2, "Verifying HMAC...")
	h := hmac.New(sha256.New, key)
	h.Write(message)
	calculatedHMAC := h.Sum(nil)
	if !hmac.Equal(calculatedHMAC, givenHMAC) {
		fail("Incorrect HMAC! Aborting.")
	}
}
