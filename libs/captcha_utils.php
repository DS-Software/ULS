<?php

require_once "../config.php";

if($captcha_required){
$script = <<<EOT
window.cpi = false;
function callCaptcha(){
	if(window.cpi){
		alertify.notify("Проверка не была пройдена. Попробуйте позже!", 'error', 3);
		window.cpi = false;
		return;
	}
	window.alert_prompt = alertify.alert('CAPTCHA', 'Your request is being processed... Wait a bit.<br><div id="captcha_content"></div>');
	captcha_content.innerHTML = '<div id="turnstile_captcha"></div>';
	turnstile.render('#turnstile_captcha', {
        sitekey: '$turnstile_public',
        callback: function(token) {
            repeatRequest(token);
        }
    });
	
	try{
		window.alert_prompt.close();
	}
	catch(e){
		console.warn(e);
	}
}

function repeatRequest(captcha){
	try{
		window.alert_prompt.close();
	}
	catch(e){
		console.warn(e);
	}
	alertify.notify("Вы успешно прошли проверку!", 'success', 3);
	document.cookie = "passed_captcha=" + captcha + ";path=/";
	window.failed_request();
	window.cpi = true;
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