<?php
	require 'config.php';
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

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">

<link href="libs/alertify.min.css" rel="stylesheet">
<script src="libs/alertify.min.js"></script>

<title>Регистрация</title>

<div class="login register">
	<h1>Регистрация</h1>
	<form action="javascript:void('interception auto-post')" id="register_form">
		<label for="username">
			<i class="fas fa-user"></i>
		</label>
		<input type="email" name="email" placeholder="Почта" id="email" required>
		<br>
		<label for="password">
			<i class="fas fa-lock"></i>
		</label>
		<input type="password" name="new_password" placeholder="Новый Пароль" id="new_password" autocomplete="new-password" required>
		<label for="pwd" style="display: none" id="pwd">
			<i class="fas fa-lock"></i>
		</label>
		<input type="text" name="pwd" id="generated" style="display: none">
		<button onclick="register(email.value, new_password.value)" class="button_login_new_long">Зарегистрироваться</button>
		<button type="button" onclick="genNewPwd()" class="button_login_new_long">Создать пароль</button>
		<button onclick="back()" class="button_additional_long">Вернуться</button
	</form>
</div>

<script>

	var f = document.querySelector('#register_form');
	f.addEventListener('submit', e => {
		e.preventDefault();
	});
	
	var xhr2 = new XMLHttpRequest();

	function register(login, password){
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
			if(reg_result.description == "emailVerificationNeeded"){
				alertify.notify("Вам было отправлено письмо для продолжения регистрации!", 'message', 2, function(){location.href = "<?php echo(htmlspecialchars($login_site)) ?>"});
			}
			if(reg_result.reason == "INVALID_EMAIL"){
				alertify.notify("Введённый E-Mail недействителен!", 'error', 5);
			}
			if(reg_result.reason == 'DISPOSABLE_EMAIL'){
				alertify.notify("Данная почта не может быть использована для регистрации!", 'error', 5);
			}
		}
	}
	
	function genNewPwd(){
		let password = generatePass();
		new_password.value = password;
		pwd.style.display = "";
		generated.style.display = "block";
		generated.value = password;
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
	
	function back(){
		location.href = "<?php echo(htmlspecialchars($login_site)); ?>";
	}
</script>