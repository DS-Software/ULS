<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">

<link href="libs/alertify.min.css" rel="stylesheet">
<script src="libs/alertify.min.js"></script>

<title>Главная</title>

<?php
require 'config.php';

if($maintenance_mode){
	?>
	<div class="main_module">
		<h1>Сервис недоступен!</h1>
		<h2>В текущий момент сервис<br> недоступен. Подробнее:</h2>
		<h2 onclick="location.href = '<?php echo($status_page) ?>'" style="text-decoration: underline; cursor: pointer;">Status Page</h2>
		<h2>Извините за причинённые неудобства!</h2>
		<br>
	</div>
	<?php
	die();
}
?>

<script>
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
			case "IPVerificationNeeded":
				location.href = "ip_verification.php";
				break;
			default:
				if(access_token.token != "" && access_token.result != "FAULT"){
					location.href = "home.php";
				}
				break;
		}
	}
</script>

<div class="login">
	<h1>Вход в DS Software ULS</h1>
	<form action="javascript:void('interception auto-post')" id="login_form">
		<label for="username">
			<i class="fas fa-user"></i>
		</label>
		<input type="text" name="username" placeholder="Логин" id="username" required>
		<br>
		<label for="password">
			<i class="fas fa-lock"></i>
		</label>
		<input type="password" name="password" placeholder="Пароль" id="password" required>
		<button onclick="login(username.value, password.value)" class="button_login_new">Войти</button>
		<button onclick="register()" class="button_additional_new">Регистрация</button>
		
		<button onclick="restore()" class="button_additional_long_nomrg">Восстановить Пароль</button>
		<button onclick="easylogin()" class="button_login_new_long_mrg">Беспарольный Вход</button>
	</form>
</div>

<script>

	var f = document.querySelector('#login_form');
	f.addEventListener('submit', e => {
		e.preventDefault();
	});
	var xhr2 = new XMLHttpRequest();

	function login(login, password){
		if(login == '' || password == ''){
			return;
		}
		
		var formData = new FormData();
		formData.append("login", login);
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
			}
			else{
				if(auth_result.description == "Success"){
					location.href = "home.php";
				}
				if(auth_result.description == "emailVerificationNeeded"){
					alertify.notify("Вам было отправлено письмо для подтверждения нового IP Адреса.", 'message', 2, function(){location.href = "ip_verification.php"});
				}
			}
		}
	}
	
	function register(){
		location.href = "register.php";
	}
	function restore(){
		location.href = "restore_password.php";
	}
	
	function easylogin(){
		location.href = "easylogin.php";
	}
</script>