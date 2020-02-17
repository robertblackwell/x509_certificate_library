<?php
/**
 * This is a utility for managing host certificates as part of the 
 * process of building "interceptor" certificates for a MITM proxy.
 *
 * passed a host name this script will test to see if there is already a
 * interceptor certificate for that host.
 *
 * If not, will request the real certificate from the host on port 443
 * 	-	generate a certificate signing request for the host with all the alt names 
 * 		in the real certificate.
 *	-	have that request signed by the BlackwellApps CA 
 *	-	save the resulting identity + certificate in the "correct" place
*/
/*
* Big tricks I had to unearth to make this work:
*
*	-	the -name option on the generation of the CA pkcs12 file. Without this
*		the key does not get the same name as the certificate when imported into
*		OSX key chain and hence the CA is "not found" when trying to verify a certificate
*		signed by the ca.
*
*	-	following on from this previous point. It is no point inmporting
*		a CA certificate into OSX KeyChain by itself as this will not allow
*		verification of certificates signed by this CA. Both the certificate and
*		private key must be imported. It seems that this is best done as a PKCS12 file.
*		I tried doing it as a combined PEM but that did not work.
*		It seems that keyChain uses the key as the identifying element, not the
*		names in the certificate.
*
*		CA key+certificate can be impoted either from the command line using 
*		the security util or using keyChain. Either way once imported the
*		the key+certificate is NOT TRUSTED and so in no good for certificate
*		verification. One must MANUALLY change the trust on the certificate.
*
*	-	sha265 - this needs to be an option on BOTH the certificate signing request
*		and the signing process otherwise Chrome (and maybe others) will complain.
*		the default digest sha2 was deprecated in 2013/4.
*	
*	-	Of somewhat lesser importance was the need to strip the passphrase from
*		keys used for webservers.
*/
class CertificateUtility
{
	public $ca_name;
	public $passing;
	public $passout;
	public $ca_home_path;
	public $ca_private_path;
	public $ca_certs_folder_path;
	public $debug;
	
	function __construct()
	{
		$this->debug = true;
		$this->top_dir = dirname(__DIR__);
		$this->ca_home_path = dirname(__DIR__);"/Users/rob/CA";
		$this->ca_private_path = $this->ca_home_path . "/private";
		$this->ca_certs_folder_path = $this->ca_home_path . "/certs";
		$this->certs_folder_path = $this->ca_certs_folder_path;
		$this->allroots = $this->top_dir . "/allroots";
		$this->root_certs = $this->allroots ."/mozilla-cacert.pem";
		$this->ca_name="BlackwellApps_CA";
		$this->passin = "blackwellapps";
		$this->passout = "blackwellapps";
	}
	function setInterceptorMode()
	{
		$this->ca_certs_folder_path = $this->ca_home_path . "/certs";
		if ($this->debug) print __FUNCTION__." " . $this->ca_certs_folder_path . "\n";
	}
	function setServerMode()
	{
		$this->ca_certs_folder_path = $this->ca_home_path . "/sites";
	}
	function ca_private_dir()
	{	
		return $this->ca_private_path;
	}
	function ca_configfile_path()
	{
		return $this->ca_home_path."/ca_config.conf";
	}
	function ca_key_path()
	{
		return $this->ca_home_path."/private/cakey.pem";
	}
	function ca_cert_path()
	{
		return $this->ca_home_path."/private/cacert.pem";
	}
	function host_dir($host)
	{
		return $this->ca_certs_folder_path."/".$host;
	}
	function host_certificate_path($host)
	{
		return $this->host_dir($host)."/interceptor_cert.pem";
	}
	function host_key_path($host)
	{
		return $this->host_dir($host)."/pass_protected_key.pem";
	}
	function host_unprotected_key_path($host)
	{
		return $this->host_dir($host)."/key.pem";
	}
	function host_request_path($host)
	{
		return $this->host_dir($host)."/request.pem";
	}
	function host_config_path($host)
	{
		return $this->host_dir($host)."/config.cnf";
	}
	function host_real_certificate_path($host)
	{
			return $this->host_dir($host)."/real_certificate.pem";
	}
	function host_p12_path($host)
	{
			return $this->host_dir($host)."/certificate.p12";
	}
	function certificateExists($host)
	{
		if ($this->debug) print __FUNCTION__ . " host : $host ";
		$hp = $this->host_certificate_path($host);
		$x = file_exists($hp);
		if ($this->debug) print " file : $hp exists : $x ";
		$res = ( (file_exists($hp)) && (! is_dir($hp)) );
		if ($this->debug) print " returning $res hp : $hp \n";
		return $res;
	}
	function rebuild_host_folder($host)
	{
		$hp = $this->host_certificate_path($host);
		$cmd = "rm -rf $hp/*";
		system($cmd);
		$this->create($host);
	}
	function get_interceptor_certificate($host)
	{
		if ($this->debug) print __FUNCTION__ ." $host \n";
		if( ! $this->certificateExists($host) ) {
			if ($this->debug) print __FUNCTION__ ." certificate does not exist\n";
			$this->create($host);
		} 
		if ($this->debug) print __FUNCTION__ ." returning " . $this->host_certificate_path($host) . "\n";
		return $this->host_certificate_path($host);
			
	}
	/**
	* Create our own Certificate Signing Authority
	*/
	function ca_create($ca_name="BlackwellApps CA", $passin="blackwellapps", $passout="blackwellapps")
	{
		$cmd=<<<EOD
openssl req -x509 -newkey rsa:2048 -out cacert.pem -days 3650 -outform PEM -config self-sign-root.cnf
openssl pkcs12 \
	-name $ca_name \
	-export \
	-out ca.p12 \
	-inkey cakey.pem \
	-in cacert.pem \
	-passin pass:$passin \
	-passout pass:$passout
	}
EOD;
	}
	/**
	* Create the intercepting certificate for a host
	*/
	function create($host)
	{
		print __FUNCTION__ ."\n";
		$this->working_dir = $this->host_dir($host);
		$this->create_host_folder($host);
		$this->get_real_host_certificate($host);
		$this->create_host_config_file($host);
		
		$this->make_signing_request($host);
		$this->sign_request($host);
		$this->removePassPhrase($host);
		$this->make_p12_file($host);
	}
	function create_from_config($host)
	{
		$this->make_signing_request($host);
		$this->sign_request($host);
		$this->make_p12_file($host);
	}
	/**
	* Create the host folder in the certificate database
	*/
	private function create_host_folder($host)
	{	
		$hd = $this->host_dir($host);
		if( ! is_dir($this->host_dir($host)) )
			system( "mkdir -p $hd" ); 
		//system('rm $hd/*');
	}
	/**
	* Using info in the hosts real certificate create an openssl config file
	* to be used in creating a certificate request and for signing that request.
	*
	* The key is getting the CN and subjectAltName from the real certificate 
	*/
	function create_host_config_file($host)
	{
		$fn = $this->host_real_certificate_path($host);
		$data = file_get_contents($fn, "r");
		$x509 = openssl_x509_read($data);
		$symbols = openssl_x509_parse($x509);
// 		print_r($symbols);
		$common_name = $symbols['subject']['CN'];
		$subjectAltNames = $symbols['extensions']['subjectAltName'];
		print "Extract from real certificate\n";
		print "common name : $common_name\n";
		print "subjectAltName : $subjectAltNames\n";
		/**
		* This requires two variables to be set:
		*
		*	$commonName - from the original certificate
		*	$alt_names - subkectAltName in a single line string
		*/
		$dir = $this->ca_home_path;
		$alt_names = $subjectAltNames;
		$cfg = //<<<EOD	
"[ ca ]
default_ca 		= exampleca

[ exampleca ]
dir 				= {$dir}
certificate 		= {$dir}/cacert.pem
database 			= {$dir}/index.txt
new_certs_dir 		= {$dir}/certs
private_key 		= {$dir}/private/cakey.pem
serial 				= {$dir}/serial

default_crl_days 	= 7
default_days 		= 365
default_md 			= md5

[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
commonName 				= {$common_name}
stateOrProvinceName 	= WA
countryName 			= US
emailAddress 			= rob@blackwellapps.com
organizationName 		= blackwellapps
organizationalUnitName 	= BlackwellApps Root Certificate

[v3_req]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
#subjectAltName = @alt_names
subjectAltName = {$alt_names}

#[alt_names]
#DNS.1 = blackwellapps.com
#DNS.2 = one.blackwellapps.com
#DNS.3 = wto.blackwellapps.com";

		$cfgfn = $this->host_config_path($host);
		file_put_contents($cfgfn, $cfg);
/**/	
	}
	/**
	* Use openssl s_client command to download the hosts real certificate
	*/
	function get_real_host_certificate($host)
	{
		print "get_real_host_certificate $host\n";

		$outfile = $this->working_dir."/real_certificate.pem";
		$cmd =<<<EOD
	openssl s_client -showcerts -CAfile {$this->root_certs}  -connect {$host}:443 </dev/null \
	| openssl x509 -outform PEM \
	| sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' \
	> {$outfile}
EOD;
		if ($this->debug) print "get real certificate : {$cmd}\n";
		system($cmd);
	}
	
	/**
	* Generate a signing request for the host and save it as a PEM file
	*/
	function make_signing_request($host)
	{
		$kp = $this->host_key_path($host);
		$rp = $this->host_request_path($host);
		$cnf = $this->host_config_path($host);
		/**
		* This is not right - must collec some info from real certificate
		* so that the new interceptor certificate has the correct names
		*/
//  		$cnf = $this->ca_configfile_path();
		
		if ($this->debug) print "make signing request $host \n";
		$cmd =<<<EOD
		openssl req -newkey \
		rsa:2048 \
		-keyout {$kp} \
		-keyform PEM \
		-out ${rp} \
		-outform PEM \
		-passout pass:blackwellapps \
		-sha256 \
		-config {$cnf}
EOD;
		system($cmd);
	}
	
	/**
	* Use openssl x509 command to sign a hosts certificate request.
	* Make sure it is a v3 certificate
	*/
	function sign_request($host)
	{
		$cak = $this->ca_key_path();
		$cac = $this->ca_cert_path();
		$rp = $this->host_request_path($host);
		$cp = $this->host_certificate_path($host);
		$cfg = $this->host_config_path($host);
		print "sign request $host\n";
		$cmd =<<<EOD
		openssl x509 -req \
	-in {$rp} \
	-inform PEM \
	-sha256 \
	-CA {$cac} \
	-CAkey {$cak} \
	-CAcreateserial \
	-extfile {$cfg} \
	-extensions v3_req \
	-out {$cp} \
	-outform PEM \
	-passin pass:blackwellapps \
	-days 500
EOD;
		print "$cmd\n";
		system($cmd);
	}
	
	function removePassPhrase($host)
	{
		$pkp = $this->host_key_path($host);
		$upkp = $this->host_unprotected_key_path($host);
		
		$cmd =<<<EOD
		openssl rsa \
			-in {$pkp} \
			-out {$upkp} \
			-passin pass:blackwellapps 
EOD;
		print "removing pass protecttion $host $pkp --> $upkp\n";
		system($cmd);
	}
	
	function make_p12_file($host)
	{	
		$key = $this->host_key_path($host);
		$cert = $this->host_certificate_path($host);
		$p12  = $this->host_p12_path($host);
		
		$cmd =<<<EOD
		openssl pkcs12 \
			-export \
			-out {$p12} \
			-inkey {$key} \
			-in {$cert} \
			-passin pass:blackwellapps \
			-passout pass:blackwellapps
EOD;
		system($cmd);
	}
	function renameCertAndKeyForServer($host)
	{
		$cp = $this->host_certificate_path($host);
		$kp = $this->host_unprotected_key_path($host);
		$new_cp = $this->host_dir($host)."/{$host}.crt.pem";
		$new_kp = $this->host_dir($host)."/{$host}.key.pem";
		print "rename : $cp --> $new_cp\n";
		print "rename : $kp --> $new_kp\n";

		system("cp $cp {$new_cp}");
		system("cp $kp {$new_kp}");
	}
	function conf($dir)
	{
		$root = $this->top_dir;
		$this->substitute_config($dir, $root);
	}
	/**
	* Load a config file template ($dir/template_config.cnf), 
	* substitutute the value $self->top_dir
	* for the variable $home and saves the substituted value
	* as $dir/config.cnf
	*/
	function config_from_template($dir)
	{
		$path = $dir ."/template_config.cnf";
		$home = $root;
		$info = new SplFileInfo($path);
		$rp = $info->getRealPath();
		$contents = file_get_contents($rp);
		$s_u = '$xx = "'.$contents.'";' ;
		eval($s_u);
		$new_content = $xx;
		file_put_contents($dir."/config.cnf", $new_content);
		print $new_content . "\n";
	}
	
}
function usage()
{
	print "\tusage : php cert-util.php <command>  <argument> \n";
	print "\t<command> is one of 'req', 'get', 'getall' help'\n\n";
	print "\t\treq\tmake a signed certificate for a <host>. \n";
	print "\t\t\tThe host folder must already exists and must contain a openssl config file config.cnf. \n\n";
	print "\t\tget\tget a real certificate from <host> and then make a signed interceptor certificate\n\n";
	print "\t\tgetall\tget a real certificate from a list of <host>s and then make signed interceptor certificates for each, will delete existing and rebuild\n\n";
	print "\t\thelp\tself explanatory\n\n";
	print "\t<argument> is a host name such as 'somedomain' or 'somedomain.com'\n";
	exit(1);
}


print "\n";
function help()
{
	usage();
}

if( $argc < 3){
	usage();
}
$command = $argv[1];
$host = $argv[2];

switch($command)
{
	case "ca-root":
		break;
	case "server":
	case "req" :
	//
	// In this mode we are using the CA to sign certificates for test servers.
	// hence we start with a conf file and gen, and then sign a CSR
	// crucially the result is put in the 'sites/$host' folder
	//
		$factory = new \CertificateUtility();
		$factory->setServerMode();
		$factory->create_from_config($host);
		$factory->removePassPhrase($host);		
		$factory->renameCertAndKeyForServer($host);
		break;
	//
	// This is the "real deal". Solicit a real certificate from a host
	//  and use it to generate an interceptor certificate.
	//  Put the results and the workings in a folder called
	//
	//	certs/<hostname>
	//
	case "get" :
		$factory = new \CertificateUtility();
		$factory->setInterceptorMode();
		$factory->get_interceptor_certificate($host);
		break;
	case "host" :
		$factory = new \CertificateUtility();
	
	case "getall" :
		$i = 0;
		for( $i = 2; $i < count($argv); $i++) {
			$host = $argv[$i];
			print "get server certificate for $host \n";

			$factory = new \CertificateUtility();
			$factory->setInterceptorMode();
			$factory->rebuild_host_folder($host);
		}		
		break;	//
	// Load a conf file, fix the path references and dump out to stdout
	//	
	case "conf":
		$factory = new \CertificateUtility();		
		$factory->conf($argv[2]);
		break;
	case "help":
		help();
		break;
	default :
		usage();
		break;
}
//if( $argc == 3){
//
//	//then we are making a request/cert without getting server original
//	$host = $argv[1];
//	$factory = new \CertificateUtility();
//	$factory->create_from_config($host);
//
//}else{
//	$host  = $argv[1];
//	print "Getting certificate for $host \n";
//	$factory = new \CertificateUtility();
//	$factory->get_interceptor_certificate($host);
//}
/*
$cmd = dirname(__DIR__)."/bin/get-server-certificate.sh  bankofamerica.com  bofa.pem";

system($cmd);

$fn = dirname(__DIR__)."/bofa.pem";
$cert = openssl_x509_read( file_get_contents($fn, "r"));
// var_dump($cert);
$c = openssl_x509_parse($cert);
print_r($c['subject']);
print_r($c['issuer']);
print "\nSerial Number : {$c['serialNumber']} \n";
print "Extensions SubjectAltName : {$c['extensions']['subjectAltName']}\n";
*/
?>