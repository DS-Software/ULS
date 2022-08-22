<link rel="stylesheet" href="style.css">
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v6.1.1/css/all.css">
<link href="libs/alertify.min.css" rel="stylesheet">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<script src="libs/main.js"></script>
<script src="libs/captcha_utils.php"></script>
<script src="libs/alertify.min.js"></script>
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Главная</title>

<?php
require 'config.php';
?>
<div class="login-form hidden-el" id="maintenance">
	<h1 class="thin-text">Сервис недоступен!</h1>
	<div class="sep-line"></div>
	<h2 class="full-width thin-text">В текущий момент сервис недоступен. Подробнее:</h2>
	<h2 onclick="location.href = '<?php echo($status_page) ?>'" class="a-element">Status Page</h2>
	<h2 class="thin-text">Извините за причинённые неудобства!</h2>
</div>

<div class="login-form" id="login_form">
	<h2 class="thin-text"><?php echo(htmlspecialchars($email_info['$project_name'])) ?></h2>
	<h1 class="thin-text">Вход</h1>
	<div class="sep-line"></div>
	<form action="javascript:void('')">
		<div class="full-width">
			<div class="align-left icon">
				<i class="fa-solid fa-user"></i>
			</div>
			<span class="input-placeholder">Ваш EMail</span>
			<input class="text-input max-width input-field-decoration" id="email" autocomplete="on">
		</div>
		<br>
		<div class="full-width">
			<div class="align-left icon">
				<i class="fa-solid fa-key"></i>
			</div>
			<span class="input-placeholder">Ваш Пароль</span>
			<input type="password" class="text-input max-width input-field-decoration" id="password" autocomplete="on">
		</div>
		<br>
		<div class="align-left full-width">
			<p class="no-mrg-top"><a onclick="restore()">Забыли пароль?</a></p>
		</div>
		<div class="align-left full-width">
			<div class="max-width">
				<button class="button-primary" onclick="login(email.value, password.value)">Войти</button>
				<button class="button-secondary float-right" onclick="register()">Создать аккаунт</button>
			</div>
		</div>
		<div class="full-width">
			<button class="button-secondary" onclick="easylogin()">Беспарольный Вход</button>
		</div>
	</form>
</div>

<div class="login-form hidden-el" id="restore_form">
	<h1 class="thin-text">Восстановление Пароля</h1>
	<div class="sep-line"></div>
	<form action="javascript:void('')">
		<div class="full-width">
			<div class="align-left icon">
				<i class="fa-solid fa-user"></i>
			</div>
			<span class="input-placeholder">Ваш EMail</span>
			<input class="text-input max-width input-field-decoration" id="email_restore" autocomplete="on">
		</div>
		<br>
		<div class="align-left full-width">
			<button class="button-primary" onclick="send_restore_message(email_restore.value)">Восстановить</button>
			<button class="button-secondary float-right" onclick="back()">Вернуться</button>
		</div>
	</form>
</div>

<div class="login-form hidden-el" id="easylogin_form">
	<h1 class="thin-text">Беспарольный Вход</h1>
	<div class="sep-line"></div>
	<h2 class="thin-text full-width">Считайте QR код на устройстве, где вход в <?php echo(htmlspecialchars($email_info['$project_name'])) ?> уже был произведён:</h2>
	<div id="QR_Container" class="full-width"><img id="session_container"></div>
	<br>
	<div class="full-width">
		<button class="button-primary" onclick="removeSession()">Вернуться</button>
	</div>
</div>

<div class="login-form hidden-el" id="register_form">
	<h1 class="thin-text">Регистрация</h1>
	<div class="sep-line"></div>
	<form action="javascript:void('')">
		<div class="full-width">
			<div class="align-left icon">
				<i class="fa-solid fa-user"></i>
			</div>
			<span class="input-placeholder">Почта</span>
			<input class="text-input max-width input-field-decoration" id="email_register" autocomplete="on">
		</div>
		<br>
		<div class="full-width">
			<div class="align-left icon">
				<i class="fa-solid fa-key"></i>
			</div>
			<span class="input-placeholder">Пароль</span>
			<input type="password" class="text-input max-width input-field-decoration" id="password_register" autocomplete="on">
		</div>
		<br>
		<div class="full-width hidden-el" id="gen_pwd">
			<div class="align-left icon">
				<i class="fa-solid fa-lock"></i>
			</div>
			<span class="input-placeholder">Новый Пароль</span>
			<input class="text-input max-width input-field-decoration" id="generated">
		</div>
		<br>
		<div class="align-left full-width">
			<button class="button-primary" onclick="send_register_message(email_register.value, password_register.value)">Продолжить</button>
			<button class="button-secondary float-right" onclick="genNewPwd()">Создать пароль</button>
		</div>
		<div class="full-width">
			<button class="button-secondary" onclick="back()">Вернуться</button>
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
			case "IPVerificationRequired":
				location.href = "check_user.php";
				break;
			default:
				if(access_token.token != "" && access_token.result != "FAULT"){
					location.href = "home.php";
				}
				break;
		}
		if(access_token.reason == "MAINTENANCE_MODE"){
			prepare_gui();
			maintenance.classList.remove('hidden-el');
		}
	}
}
	
var xhr2 = new XMLHttpRequest();

function prepare_gui(){
	login_form.classList.add('hidden-el');
	restore_form.classList.add('hidden-el');
	easylogin_form.classList.add('hidden-el');
	register_form.classList.add('hidden-el');
}

/*
	Login functions
*/

function login(user_login, password){
	if(user_login == '' || password == ''){
		return;
	}
	
	var formData = new FormData();
	formData.append("login", user_login);
	formData.append("password", password);

	xhr2.open("POST", "api.php?section=UNAUTH&method=authorize");
	xhr2.send(formData);

	xhr2.onload = function (e) {
		let auth_result = JSON.parse(xhr2.responseText);		
		if(auth_result.result == 'FAULT'){
			if(auth_result.reason == 'WRONG_CREDENTIALS'){
				alertify.notify("Неверный логин и/или пароль!", 'error', 5);
			}
			if(auth_result.reason == 'DISPOSABLE_EMAIL'){
				alertify.notify("Данная почта не может быть использована для входа!", 'error', 5);
			}
			if(auth_result.reason == 'ACCOUNT_BANNED'){
				alertify.notify("Данный аккаунт был заблокирован Администрацией проекта. Больше информации: " + auth_result.support, 'error', 5);
			}
			if(auth_result.reason == "RATE_LIMIT_EXCEEDED"){
				window.failed_request = function(){
					login(user_login, password);
				};
				callCaptcha();
			}
		}
		else{
			checkAPIToken();
		}
	}
}

function back(){
	prepare_gui();
	login_form.classList.remove('hidden-el');
}

/*
	Restore functions
*/
	
function send_restore_message(login){
	if(login == ''){
		return;
	}
	xhr2.open('GET', 'api.php?section=UNAUTH&method=sendRestoreEmail&login=' + login, true);
	xhr2.send();
	xhr2.onload = function (e) {
		let api_response = JSON.parse(xhr2.responseText);
		if(api_response.description == "emailVerificationRequired"){
			back();
			alertify.notify("Вам было отправлено письмо для восстановления пароля!", 'message', 2);
		}
		if(api_response.reason == "INVALID_EMAIL"){
			alertify.notify("Введённый E-Mail недействителен!", 'error', 5);
		}
		if(api_response.reason == 'DISPOSABLE_EMAIL'){
			alertify.notify("Данная почта не может быть использована для входа!", 'error', 5);
		}
		if(api_response.reason == "RATE_LIMIT_EXCEEDED"){
			window.failed_request = function(){
				send_restore_message(login);
			};
			callCaptcha();
		}
	}
}

function restore(){
	prepare_gui();
	restore_form.classList.remove('hidden-el');
}

/*
	Easylogin functions
*/
	
function prepare_easylogin(){
	xhr2.open('GET', 'api.php?section=UNAUTH&method=getELSession', true);
	xhr2.send();
	xhr2.onload = function (e) {
		let session = JSON.parse(xhr2.responseText);
		if(session.result == "OK"){
			window.el_session = session.session;
			window.session_verifier = session.session_verifier;
			
			var el = document.getElementById("session_container");
			el.src = session.session_qr;
			
			window.timeout = setTimeout(removeSession, 300000);
			window.interval = setInterval(checkSession, 400);
		}
		else{
			alertify.notify("Ошибка при получении сессии EasyLogin. Войдите обычным путём.", 'error', 2, removeSession);
		}
	}
}
	
function checkSession(){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=checkELSession&session_id=' + window.el_session + "&session_ver=" + window.session_verifier, true);
	xhr.send();
	xhr.onload = function (e) {
		let handler = JSON.parse(xhr.responseText);
		if(handler.result == "OK"){
			location.reload();
			clearInterval(window.interval);
			return;
		}
		if(handler.result == "FAULT" && handler.reason == "UNCLAIMED"){
			return;
		}
		if(handler.result == "FAULT" && handler.reason == "THIS_FEATURE_WAS_DISABLED_BY_OWNER"){
			clearInterval(window.interval);
			alertify.notify("Чтобы использовать EasyLogin вам необходимо включить его в ЛК!", 'error', 2, removeSession);
			return;
		}
		if(handler.result == "FAULT" && handler.reason == "WRONG_SESSION"){
			clearInterval(window.interval);
			return;
		}
			
		clearInterval(window.interval);
		alertify.notify("Произошла ошибка при обновлении статуса сессии!", 'error', 2, removeSession);
	}
}
	
function showExpiredMessage(){
	alertify.notify("Время сессии закончилось, повторите попытку!", 'error', 2, removeSession);
}
	
function removeSession(){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=removeELSession&session_id=' + window.el_session + "&session_ver=" + window.session_verifier, true);
	xhr.send();
		
	clearTimeout(window.timeout);
	clearInterval(window.interval);
		
	back();
}

function easylogin(){
	prepare_gui();
	easylogin_form.classList.remove('hidden-el');
	prepare_easylogin();
}

/*
	Register functions
*/

function register(){
	prepare_gui();
	register_form.classList.remove('hidden-el');
}

function genNewPwd(){
	let password = generatePass();
	password_register.value = password;
	gen_pwd.classList.remove('hidden-el');
	generated.value = password;
	generated.previousElementSibling.classList.add('placeholder-upper');
}
	
function generatePass(){
	let arr = window.crypto.getRandomValues(new BigUint64Array(1))[0].toString(36).split("");
	arr = arr.concat(window.crypto.getRandomValues(new BigUint64Array(1))[0].toString(36).split(""));
	arr = arr.slice(0, 16);
	arr.forEach(function(element, index){
		if(Math.round(Math.random())){
			arr[index] = element.toUpperCase();
		}
	});
		
	return arr.join("");
}

function send_register_message(login, password){
	if(login == '' || password == ''){
		return;
	}
		
	var formData = new FormData();
	formData.append("login", login);
	formData.append("password", password);

	xhr2.open("POST", "api.php?section=UNAUTH&method=sendRegisterMessage");
	xhr2.send(formData);
		
	xhr2.onload = function (e) {
		let reg_result = JSON.parse(xhr2.responseText);
		if(reg_result.description == "emailVerificationRequired"){
			alertify.notify("Вам было отправлено письмо для продолжения регистрации!", 'message', 2, back);
		}
		if(reg_result.reason == "INVALID_EMAIL"){
			alertify.notify("Введённый E-Mail недействителен!", 'error', 5);
		}
		if(reg_result.reason == 'DISPOSABLE_EMAIL'){
			alertify.notify("Данная почта не может быть использована для регистрации!", 'error', 5);
		}
		if(reg_result.reason == "RATE_LIMIT_EXCEEDED"){
			window.failed_request = function(){
				send_register_message(login, password);
			};
			callCaptcha();
		}
	}
}
</script>