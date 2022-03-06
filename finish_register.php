<?php
	require 'config.php';
?>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Завершение регистрации</title>

<link href="libs/alertify.min.css" rel="stylesheet">
<script src="libs/alertify.min.js"></script>

<script>
	window.login_url = "<?php echo(htmlspecialchars($login_site)) ?>";

	var token_xhr = new XMLHttpRequest();
	var xhr = new XMLHttpRequest();
	token_xhr.open('GET', login_url + '/api.php?section=UNAUTH&method=getAccessToken', true);
	token_xhr.send();
	token_xhr.onload = function (e) {
		let access_token = JSON.parse(token_xhr.responseText);
		switch (access_token.description) {
			case "2faVerificationRequired":
				location.href = login_url + "/2fa_check.php";
				break;
			default:
				window.token = access_token.token;
				bootstrap();
				break;
		}
	}
	
	function bootstrap(){
		if(window.token == "" || window.token == undefined){
			location.href = login_url;
		}
		else{
			loadUserInfo();
		}
	}
	
	function sendrequest(tag, name, surname, bday){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', login_url + '/api.php?section=register&method=saveInfo&user_name=' + encodeURIComponent(name) + '&user_surname=' + encodeURIComponent(surname) + '&user_nick=' + encodeURIComponent(tag) + '&birthday=' + encodeURIComponent(bday), true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			let ret = JSON.parse(xhr.responseText);
			if(ret.result == "FAULT"){
				if(ret.reason == "MALFORMED_NICK"){
					alertify.notify('Tag Пользователя занят, либо содержит запрещённые знаки!', 'error', 5);
					return;
				}
				
				if(ret.reason == "MALFORMED_NAME"){
					alertify.notify('Имя содержит запрещённые знаки!', 'error', 5);
					return;
				}
				
				if(ret.reason == "MALFORMED_SURNAME"){
					alertify.notify('Фамилия содержит запрещённые знаки!', 'error', 5);
					return;
				}
				if(ret.reason == "MALFORMED_BIRTHDAY"){
					alertify.notify('Дата Рождения не указана!', 'error', 5);
					return;
				}
				alertify.notify('Произошла непредвиденная ошибка!', 'error', 5);
			}
			else{
				location.href = "index.php";
			}
		}
	}
	
	function back(){
		location.href = "<?php echo(htmlspecialchars($int_url)) ?>";
	}
</script>

<div class="main_module" style="margin-top: 3%;">
	<h1>Личная Информация</h1>
	<h2 style="margin-bottom: 0px;">Для продолжения, заполните поля ниже:</h2>
	<h2 style="color: #888; margin-top: 0px;">Эти данные используются исключительно для персонализации сервисов!</h2>
	<form action="javascript:void('')" style="">
		<p style="display: flex;flex-wrap: wrap;justify-content: center;">
			<label for="nickname" class="label">
				<i class="fas fa-user-tag"></i>
			</label>
			<input type="text" name="nick" placeholder="User Tag" id="nick" maxlength="16" required>
			<p style></p>
		</p>
		
		<p style="display: flex;flex-wrap: wrap;justify-content: center;">
			<label for="user_name" class="label">
				<i class="fas fa-user-edit"></i>
			</label>
			<input type="text" name="name" placeholder="Ваше Имя" id="uname" maxlength="32" required>
		</p>

		<p style="display: flex;flex-wrap: wrap;justify-content: center;">
			<label for="user_surname" class="label">
				<i class="fas fa-user-plus"></i>
			</label>
			<input type="text" name="surname" placeholder="Ваша Фамилия" id="usurname" maxlength="32" required>
		</p>
		
		<p style="display: flex;flex-wrap: wrap;justify-content: center;">
			<label for="user_birthday" class="label">
				<i class="fas fa-birthday-cake"></i>
			</label>
			<input type="date" name="bday" placeholder="День Рождения" id="ubday" min="1900-01-01" required>
		</p>
	</form>
	<button class="button_submit" onclick="continue_reg()" id="save">Продолжить</button>
	<br>
</div>

<script>
var input = document.getElementById('nick');
var input2 = document.getElementById('uname');
var input3 = document.getElementById('usurname');
var input4 = document.getElementById('ubday');

function loadUserInfo(){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=users&method=getCurrentEmail', true);
	xhr.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr.send();
	xhr.onload = function (e) {
		let result = JSON.parse(xhr.responseText);
		
		if(result.result == "OK"){
			input.value = result.user_nick;
			input2.value = result.user_name;
			input3.value = result.user_surname;
			input4.valueAsNumber = result.user_bday * 1000;
		}
	}
}

function continue_reg(){
	if(input.value.length >= 3 && 16 >= input.value.length){
		if(input2.value.length >= 2 && 32 >= input2.value.length){
			if(input3.value.length >= 2 && 32 >= input3.value.length){
				if(input4.valueAsNumber / 1000 != 0){
					sendrequest(input.value, input2.value, input3.value, input4.valueAsNumber / 1000);
				}
				else{
					alertify.notify('Укажите свою дату рождения!', 'error', 5);
				}
			}
			else{
				alertify.notify('Фамилия не должна быть короче 2 символов!', 'error', 5);
			}
		}
		else{
			alertify.notify('Имя не должно быть короче 2 символов!', 'error', 5);
		}
	}
	else{
		alertify.notify('Tag Пользователя не должен быть короче 3 символов!', 'error', 5);
	}
}
</script>