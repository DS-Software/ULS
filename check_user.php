<link rel="stylesheet" href="style.css">
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v6.1.1/css/all.css">
<link href="libs/alertify.min.css" rel="stylesheet">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<script src="libs/main.js"></script>
<script src="libs/captcha_utils.php"></script>
<script src="libs/alertify.min.js"></script>
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Подтверждение Входа</title>

<div class="login-form hidden-el" id="TOTP_Prompt">
	<h1 class="thin-text">Проверка 2FA</h1>
	<div class="sep-line"></div>
	<h2 class="full-width thin-text">Введите код, полученный из приложения-генератора кодов 2FA.</h2>
	<form action="javascript:void('')">
		<div class="full-width">
			<div class="align-left icon">
				<i class="fa-solid fa-lock"></i>
			</div>
			<span class="input-placeholder">Код 2FA</span>
			<input type="number" class="text-input max-width input-field-decoration" id="otp" autocomplete="off">
		</div>
		<br>
		<div class="align-left full-width">
			<button class="button-primary" onclick="checkTOTP(otp.value)">Продолжить</button>
			<button class="button-secondary float-right" onclick="logout()">Выйти</button>
		</div>
		<div class="full-width">
			<button class="button-secondary" onclick="showTOTPDisableMenu()">Отключить 2FA</button>
		</div>
	</form>
</div>

<div class="login-form hidden-el" id="IP_Prompt">
	<h1 class="thin-text">Новый IP</h1>
	<div class="sep-line"></div>
	<h2 class="full-width thin-text">Введите код, отправленный на указанную ранее почту.</h2>
	<form action="javascript:void('')">
		<div class="full-width">
			<div class="align-left icon">
				<i class="fa-solid fa-lock"></i>
			</div>
			<span class="input-placeholder">Код Подтверждения</span>
			<input class="text-input max-width input-field-decoration" id="email_code">
		</div>
		<br>
		<div class="align-left full-width">
			<p class="no-mrg-top"><a onclick="resend_email()">Отправить код повторно</a></p>
		</div>
		<div class="align-left full-width">
			<button class="button-primary" onclick="checkIP(email_code.value)">Продолжить</button>
			<button class="button-secondary float-right" onclick="logout()">Выйти</button>
		</div>
	</form>
</div>

<div class="login-form hidden-el" id="DIS_Prompt">
	<h1 class="thin-text">Отключение 2FA</h1>
	<div class="sep-line"></div>
	<h2 class="full-width thin-text">Введите код отключения 2FA, созданный при включении 2FA.</h2>
	<form action="javascript:void('')">
		<div class="full-width">
			<div class="align-left icon">
				<i class="fa-solid fa-lock"></i>
			</div>
			<span class="input-placeholder">Код Отключения</span>
			<input class="text-input max-width input-field-decoration" id="disable_code">
		</div>
		<br>
		<div class="align-left full-width">
			<button class="button-primary" onclick="disableTOTP(disable_code.value)">Продолжить</button>
			<button class="button-secondary float-right" onclick="continue_check('TOTP')">Вернуться</button>
		</div>
	</form>
</div>

<script>
prepare_view();
checkRequirements();

function checkRequirements(){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	xhr.send();
	xhr.onload = function (e) {
		let access_token = JSON.parse(xhr.responseText);
		switch (access_token.description) {
			case "2faVerificationRequired":
				continue_check("TOTP");
				break;
			case "IPVerificationRequired":
				continue_check("IP");
				break;
			case "unfinishedReg":
				location.href = "finish_register.php";
				break;
			default:
				if(access_token.result == "FAULT"){
					location.href = "index.php";
				}
				else{
					location.href = "home.php";
				}
				break;
		}
	}
}

var xhr2 = new XMLHttpRequest();

function continue_check(type){
	prepare_gui();
	
	if(type == "TOTP"){
		TOTP_Prompt.classList.remove('hidden-el');
	}
	
	if(type == "IP"){
		IP_Prompt.classList.remove('hidden-el');
	}
}

/*
	TOTP Check Functions
*/

function checkTOTP(totp_code){
	if(totp_code.length != 6){
		alertify.notify("Код должен быть шестизначным!", 'warning', 5);
		return;
	}
	
	xhr2.open('GET', 'api.php?section=UNAUTH&method=checkTOTP&otp=' + totp_code, true);
	xhr2.send();
	xhr2.onload = function (e) {
		let json = JSON.parse(xhr2.responseText);
		if(json.result == "FAULT"){
			if(json.reason == "WRONG_2FA_CODE"){
				alertify.notify("Вы ввели неверный код двухфакторной аутентификации!", 'error', 5);
				return;
			}
			if(json.reason == "RATE_LIMIT_EXCEEDED"){
				window.failed_request = function(){
					checkTOTP(totp_code);
				};
				callCaptcha();
				return;
			}
			alertify.notify("Произошла ошибка при проверке кода двухфакторной аутентификации.", 'error', 5);
		}
		else{
			alertify.notify("Вы успешно прошли проверку!", 'success', 2, checkRequirements);
		}
	}
}

function showTOTPDisableMenu(){
	prepare_gui();
	DIS_Prompt.classList.remove('hidden-el');
}

function disableTOTP(key){
	xhr2.open('GET', 'api.php?section=UNAUTH&method=disableTOTP&key=' + key, true);
	xhr2.send();
	xhr2.onload = function (e) {
		let json = JSON.parse(xhr2.responseText);
		if(json.result == "OK"){
			alertify.notify("Вы успешно отключили Двухфакторную Аутентификацию!", 'success', 2, checkRequirements);
		}
		else{
			if(json.reason == "WRONG_DISABLE_KEY"){
				alertify.notify("Введённый код отключения Двухфакторной Аутентификации недействителен!", 'error', 5);
				return;
			}
			if(json.reason == "RATE_LIMIT_EXCEEDED"){
				window.failed_request = function(){
					disableTOTP(key);
				};
				callCaptcha();
				return;
			}
			alertify.notify("Произошла ошибка при попытке отключения 2FA.", 'error', 5);
		}
	}
}

/*
	IP Check Functions
*/

function checkIP(ip_ver_code){
	if(ip_ver_code.length != 8){
		alertify.notify("Код должен быть восьмизначным!", 'warning', 5);
		return;
	}
	
	xhr2.open('GET', 'api.php?section=UNAUTH&method=verifyIP&code=' + ip_ver_code, true);
	xhr2.send();
	xhr2.onload = function (e) {
		let json = JSON.parse(xhr2.responseText);
		if(json.result == "FAULT"){
			if(json.reason == "WRONG_VER_CODE"){
				alertify.notify("Вы ввели неверный Код Подтверждения!", 'error', 5);
				return;
			}
			if(json.reason == "RATE_LIMIT_EXCEEDED"){
				window.failed_request = function(){
					checkIP(ip_ver_code);
				};
				callCaptcha();
				return;
			}
			alertify.notify("Произошла непредвиденная ошибка!", 'error', 5);
		}
		else{
			alertify.notify("Вы успешно прошли проверку!", 'success', 2, checkRequirements);
		}
	}
}

function resend_email(){
	xhr2.open('GET', 'api.php?section=UNAUTH&method=sendIPCode', true);
	xhr2.send();
	xhr2.onload = function (e) {
		let json = JSON.parse(xhr2.responseText);
		if(json.result == "FAULT"){
			if(json.reason == "RATE_LIMIT_EXCEEDED"){
				window.failed_request = function(){
					resend_email();
				};
				callCaptcha();
				return;
			}
			else{
				alertify.notify("Во время выполнения запроса произошла ошибка!", 'error', 5);
			}
		}
		else{
			alertify.notify("Письмо было отправлено повторно, проверьте почту.", 'success', 2);
		}
	}
}

//################################

function logout(){
	document.cookie = 'user_id=; Max-Age=0;';
	document.cookie = 'email=; Max-Age=0;';
	document.cookie = 'user_ip=; Max-Age=0;';
	document.cookie = 'user_verkey=; Max-Age=0;';
	document.cookie = 'session=; Max-Age=0;';
	document.cookie = 'SLID=; Max-Age=0;';
	document.cookie = 'ip_verify=; Max-Age=0;';
	location.href = "index.php";
}

function prepare_gui(){
	IP_Prompt.classList.add('hidden-el');
	TOTP_Prompt.classList.add('hidden-el');
	DIS_Prompt.classList.add('hidden-el');
}
</script>