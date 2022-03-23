<?php

if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) { $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP']; }

/*
	$secure_key is a private key that is used to verify external data.
	$site is a URL of your project.
	$domain_name is a path that cookies will belong to.
	
	$login_provider is a URL of your login provider.
	$scopes are access token scopes.
	$project_public is a public ULS key of your project.
	$project_secret is a secret ULS key of your project.
	$extended_auth is a flag for extended authentication.
	
	($login_url AND $login_api WILL BE AUTO-GENERATED)
*/

// ========================
// Project Settings
// ========================

$secure_key = "";

$site = "https://example.com";

$domain_name = "/";

// ========================
// Login Settings
// ========================

$login_provider = "https://login.ds-software.xyz/";

$scopes = "personal, email";

$project_public = "";

$project_secret = "";

$extended_auth = true;
/*
	If you are using extended authentication, your servers will make requests to
	your login provider's servers to verify user using the provided access token.
	
	Advantages:
		- Security. It authenticates user a lot deeper than normal sessions.
		- Security Features. Changing ULS's API Seed or SLID will revoke the access token.
		  Disabling extended authentication will disable all ULS security features as well.
	
	Disadvantages:
		- Extended authentication requires more resourses, such as bandwidth or CPU.
		- Needs more time to issue access token to user, as it makes an API request
		  to your login provider's servers.
*/

$login_url = $login_provider . "external_auth.php?public=" . $project_public . "&onFault=" . urlencode($site) . "&sign=" . hash("sha256", $site . $project_secret) . "&scopes=" . $scopes;

$login_api = $login_provider;

?>