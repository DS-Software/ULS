<?php
	require 'config.php';
?>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>EasyLogin</title>

<link href="libs/alertify.min.css" rel="stylesheet">
<script src="libs/alertify.min.js"></script>

<script>

	function back(){
		location.href = "<?php echo(htmlspecialchars($login_site)); ?>";
	}

	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	xhr.send();
	xhr.onload = function (e) {
		let access_token = JSON.parse(xhr.responseText);
		switch (access_token.description) {
			case "2faVerificationRequired":
				location.href = "2fa_check.php";
				break;
			case "unfinishedReg":
				location.href = "finish_register.php";
				break;
			default:
				if(access_token.token != "" && access_token.result != "FAULT"){
					window.token = access_token.token;
				}
				else{
					back();
				}
				break;
		}
	}
</script>

<?php

if(!hash("sha256", base64_decode($_GET['user_agent']) . "_" . $service_key) == $_GET['user_agent_ver']){
	echo("<script>window.close();</script>");
}
else{
	$user_agent = json_decode(base64_decode($_GET['user_agent']), true);
	$browser = htmlentities($user_agent['browser']);
	$version = htmlentities($user_agent['version']);
	$platform = htmlentities($user_agent['platform']);
	$ip = htmlentities($user_agent['ip']);
}

?>

<div class="login" align="center">
	<h1>Беспарольный Вход</h1>
	<h2 style="width: 90%">Вы уверены, что хотите подтвердить это устройство?</h2>
	<?php 
	echo("<h2>$browser<br>Версия: $version<br>ОС: $platform<br>IP: $ip</h2>");
	?>
		
	<button class="button_login_new_totp" onclick="accept()">Подтвердить</button>
	<button class="button_cancel_new_mrg" onclick="cancel()">Отклонить</button>
	<br>
</div>

<script>

function accept(){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=easylogin&method=claim&session_id=' + "<?php echo(htmlspecialchars($_GET['session_id'])) ?>&session_ver=<?php echo(htmlspecialchars($_GET['session_ver'])) ?>&ip=<?php echo(htmlspecialchars($ip)) ?>", true);
	xhr.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr.send();
	xhr.onload = function (e) {
		let result = JSON.parse(xhr.responseText);
		if(result.result != "OK"){
			if(result.reason == "THIS_FEATURE_WAS_DISABLED_BY_OWNER"){
				alertify.notify("EasyLogin был отключён!", 'error', 2, function(){back()});
			}
			if(result.reason == "TIMEOUT"){
				alertify.notify("Запрос не может быть подтверждён, так как он истёк!", 'error', 2, function(){back()});
			}
			if(result.reason == "UNAUTHORIZED"){
				alertify.notify("Вы не можете подтвердить запрос!", 'error', 2, function(){back()});
			}
			if(result.reason == "WRONG_SESSION"){
				alertify.notify("Сессия не найдена!", 'error', 2, function(){back()});
			}
			if(result.reason == "2FA_DISABLED"){
				alertify.notify("Вы не можете подтвердить сессию без включённого 2FA!", 'error', 2, function(){back()});
			}
		}
		else{
			back();
		}
	}
}

function cancel(){
	back();
}

</script>