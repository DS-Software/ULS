<?php

require_once "../config.php";

if($captcha_required){
$script = <<<EOT
function callCaptcha(){
	window.alert_prompt = alertify.prompt('CAPTCHA', '<div id="captcha_content"></div>', '',
		function(evt, value){
			repeatRequest(value);
		},
		function(){
			console.log("Cancelled CAPTCHA Event");
		}
	);
	captcha_content.innerHTML = '<div class="align-center">Введите символы с картинки ниже:<br><br><img src="$login_site/captcha/"></div><br>';
}

function repeatRequest(captcha){
	document.cookie = "passed_captcha=" + captcha + ";path=/";
	window.failed_request();
}
EOT;
}
else{
$script = <<<EOT
function callCaptcha(){
	alertify.warning("Вы превысили лимит запросов!");
}

function repeatRequest(captcha){
	console.log("CAPTCHA is disabled!");
}
EOT;
}

echo($script);

?>