<link rel="stylesheet" href="style.css">
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v6.1.1/css/all.css">
<link href="libs/alertify.min.css" rel="stylesheet">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<script src="libs/main.js"></script>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<script src="libs/captcha_utils.php"></script>
<script src="libs/alertify.min.js"></script>
<script src="libs/qr_reader.min.js" async defer></script>
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Беспарольный вход</title>

<script>
window.params = (new URL(document.location)).searchParams;

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

<script>
prepare_view();
checkAPIToken();

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
					showData();
				}
				break;
		}
	}
}

function accept(){
	var xhr = new XMLHttpRequest();
	let session_id = window.params.get('session_id');
	let session_ver = window.params.get('session_ver');
	let ip = window.params.get('ip');
	xhr.open('GET', 'api.php?section=easylogin&method=claim&session_id=' + session_id +"&session_ver=" + session_ver + "&ip=" + ip, true);
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
	var xhr = new XMLHttpRequest();
	let user_agent = window.params.get('user_agent');
	let user_agent_ver = window.params.get('user_agent_ver');
	xhr.open('GET', 'api.php?section=easylogin&method=checkELInfo&user_agent=' + user_agent +"&user_agent_ver=" + user_agent_ver, true);
	xhr.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr.send();
	xhr.onload = function (e) {
		let result = JSON.parse(xhr.responseText);
		if(result.result == "OK"){
			browser.textContent = "Браузер: " + result.browser;
			version.textContent = "Версия: " + result.version;
			platform.textContent = "ОС: " + result.platform;
			ip.textContent = "IP: " + result.ip;
			return;
		}
		back();
	}
}

</script>