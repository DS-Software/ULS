<?php

function safe_encrypt($data, $password){
	$method = "aes128";
	$iv_length = openssl_cipher_iv_length($method);
	$iv = openssl_random_pseudo_bytes($iv_length);
	$data_hash = hash("sha256", $data);

	$encrypted_message = openssl_encrypt($data, $method, $password, 0, $iv);
	
	$final_message = base64_encode($data_hash . ":" . base64_encode($iv) . ":" . $encrypted_message);

	return $final_message;
}

function safe_decrypt($data, $password){
	$method = "aes128";
	$exp_data = explode(":", base64_decode($data));
	
	$data_hash = $exp_data[0];
	$iv = base64_decode($exp_data[1]);
	$encrypted_message = $exp_data[2];
	
	$decrypted_message = openssl_decrypt($encrypted_message, $method, $password, 0, $iv);
	
	if(hash("sha256", $decrypted_message) == $data_hash){
		return $decrypted_message;
	}
	else{
		return False;
	}
}

?>