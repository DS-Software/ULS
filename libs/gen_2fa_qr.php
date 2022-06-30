<?php

require_once "phpqrcode.php";
require_once "Base32.php";
require_once "Hotp.php";
require_once "Totp.php";

use lfkeitel\phptotp\{Base32,Totp};

$QR = new QRcode();

if($_GET['method'] == "TOTP" || $_GET['method'] == ''){

	function remove_spaces($string){
		return str_replace(" ", "%20", $string);
	}

	$totp_instance = new Totp();
	$base32 = new Base32();

	$final_secret = $_GET['secret'];

	$first_name = $_GET['fn'];
	$email = $_GET['email'];

	$key_name = remove_spaces("{$first_name}:{$email}");
	$issuer = remove_spaces($first_name);

	$QR_Base = "otpauth://totp/{$key_name}?secret={$final_secret}&issuer={$issuer}";
	$QR->png($QR_Base);
}

if($_GET['method'] == "EasyLoginSession"){
	$QR_Base = base64_decode($_GET['session']);
	
	$QR->png($QR_Base);
}

?>