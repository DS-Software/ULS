<?php

require_once "Base32.php";
require_once "Hotp.php";
require_once "Totp.php";
require_once "browser_libs.php";
	
use lfkeitel\phptotp\{Base32, Totp};

function TOTPInstance(){
	return new Totp();
}

function Base32Instance(){
	return new Base32();
}
	
?>