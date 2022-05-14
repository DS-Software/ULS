<link rel="stylesheet" href="style.css">
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v6.1.1/css/all.css">
<link href="libs/alertify.min.css" rel="stylesheet">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<script src="libs/main.js"></script>
<script src="libs/captcha_utils.php"></script>
<script src="libs/alertify.min.js"></script>
<script src="libs/qr_reader.min.js" async defer></script>
<meta name="viewport" content="width=device-width, initial-scale=1">

<?php
	require 'config.php';
?>

<title>Беспарольный вход</title>

<script>
function back(){
	window.close();
	location.href = "index.php";
}
</script>

<div class="login-form">
	<h1 class="thin-text">Подтверждение Устройства</h1>
	<div class="sep-line"></div>
	<form action="javascript:void('')">
		<div class="full-width">
			<h2 class="thin-text">Вы уверены, что хотите подтвердить это устройство?</h2>
			<h3 class="thin-text" id="browser"></h3>
			<h3 class="thin-text" id="version"></h3>
			<h3 class="thin-text" id="platform"></h3>
			<h3 class="thin-text" id="ip"></h3>
		</div>
		<br>
		<div class="align-left full-width">
			<button class="button-primary" onclick="accept()">Подтвердить</button>
			<button class="button-secondary float-right" onclick="back()">Вернуться</button>
		</div>
	</form>
</div>

<?php

if(!hash("sha256", base64_decode($_GET['user_agent']) . "_" . $service_key) == $_GET['user_agent_ver']){
	echo("<script>back();</script>");
}
else{
	$user_agent = json_decode(base64_decode($_GET['user_agent']), true);
	$browser = htmlentities($user_agent['browser']);
	$version = htmlentities($user_agent['version']);
	$platform = htmlentities($user_agent['platform']);
	$ip = htmlentities($user_agent['ip']);
}

?>

<script>
prepare_view();
checkAPIToken();
showData();

function checkAPIToken(){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	xhr.send();
	xhr.onload = function (e) {
		let access_token = JSON.parse(xhr.responseText);
		switch (access_token.description) {
			case "2faVerificationRequired":
				location.href = "check_user.php";
				break;
			case "unfinishedReg":
				location.href = "home.php";
				break;
			case "IPVerificationRequired":
				location.href = "check_user.php";
				break;
			default:
				if(access_token.token == "" || access_token.result == "FAULT"){
					location.href = "index.php";
				}
				else{
					window.token = access_token.token;
				}
				break;
		}
	}
}

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
			if(result.reason == 'RATE_LIMIT_EXCEEDED'){
				window.failed_request = function(){
					accept();
				};
				callCaptcha();
			}
		}
		else{
			back();
		}
	}
}

function showData(){
	browser.textContent = "Браузер: <?php echo($browser) ?>";
	version.textContent = "Версия: <?php echo($version) ?>";
	platform.textContent = "ОС: <?php echo($platform) ?>";
	ip.textContent = "IP: <?php echo($ip) ?>";
}

</script>