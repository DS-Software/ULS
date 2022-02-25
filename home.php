<?php
	require 'config.php';
?>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Аккаунт</title>

<script>
	var token_xhr = new XMLHttpRequest();
	var xhr = new XMLHttpRequest();
	token_xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	token_xhr.send();
	token_xhr.onload = function (e) {
		let access_token = JSON.parse(token_xhr.responseText);
		if(access_token.description == "2faVerificationRequired"){
			location.href = "2fa_check.php";
		}
		else{
			if(access_token.token != "" && access_token.result != "FAULT"){
				window.token = access_token.token;
				bootstrap();
			}
			else{
				window.token = "";
				bootstrap();
			}
		}
	}
	
	function bootstrap(){
		if(window.token == ""){
			location.href = "<?php echo($login_site) ?>";
		}
		else{
			getUserEmail();
		}
	}
	
	function getUserEmail(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=users&method=getCurrentEmail', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				let el = document.getElementById('email_span');
				
				el.innerHTML = result.email;
				window.email = result.email;
			}
		}
	}
	
	function logout(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=users&method=logout', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			location.reload();
		}
	}
	
	function regenerate_api(){
		var confirmed = confirm("Этим действием вы перевыпустите ваш API ключ! Это обнулит ваш предыдущий API ключ!");
		if(confirmed){
			xhr.open('GET', 'api.php?section=users&method=regenerate_api_key', true);
			xhr.setRequestHeader("Authorization", "Bearer " + window.token);
			xhr.send();
			xhr.onload = function (e) {
				location.reload();
			}
		}
	}
	
	function regenerate_slid(){
		var confirmed = confirm("Этим действием вы перевыпустите ID вашей сессии! Это приведёт к принудительному закрытию всех сеансов!");
		if(confirmed){
			xhr.open('GET', 'api.php?section=users&method=regenerate_slid', true);
			xhr.setRequestHeader("Authorization", "Bearer " + window.token);
			xhr.send();
			xhr.onload = function (e) {
				location.reload();
			}
		}
	}
	
	function show_api_management(){
		let el = document.getElementById('api_management');
		el.style.display = (el.style.display == 'none') ? '' : 'none';
	}
	
	function totp_management(){
		location.href = "2fa_mgmt.php";
	}
	
	function easylogin_mgmt(){
		location.href = "easylogin_mgmt.php";
	}
	
	function showAPIKey(){
		let el = document.getElementById('api');
		el.innerHTML = window.token;
		el.style.display = (el.style.display == 'none') ? '' : 'none';
	}
	
	var input = document.getElementById('new_un');
	var input2 = document.getElementById('password_change');
	var input3 = document.getElementById('password');
	
	function changePassword(){
		let el = document.getElementById('password_changer');
		el.style.display = (el.style.display == 'none') ? '' : 'none';
		input2.value = "";
		if(input.value == ""){
			document.getElementById('save').style.display = 'none';
		}
	}
	
	function submitPasswordChange(){
		var password_new = document.getElementById('new_password').value;
		var pwd_old = document.getElementById('password').value;
		var passwordChangeEnsurance = confirm("Вы уверены что хотите сменить пароль?");
		if(passwordChangeEnsurance){
			document.cookie = "new_password_current=" + encodeURIComponent(pwd_old) + "; max-age=120";
			document.cookie = "new_password_new=" + encodeURIComponent(password_new) + "; max-age=120";
			var xhr = new XMLHttpRequest();
			xhr.open('GET', 'api.php?section=users&method=changeUserPassword', true);
			xhr.setRequestHeader("Authorization", "Bearer " + window.token);
			xhr.send();
			xhr.onload = function (e) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					location.reload();
				}
				else{
					if(result.reason == "WRONG_PASSWORD"){
						alert("Вы ввели неверный пароль!");
					}
					return false;
				}
			}
		}
		else{
			return false;
		}
	}
	
	function changeEmail(){
		let el = document.getElementById('email_changer');
		el.style.display = (el.style.display == 'none') ? '' : 'none';
		input.value = "";
		if(input2.value == ""){
			document.getElementById('save').style.display = 'none';
		}
	}
	function submitEmailChange(){
		var email_new = document.getElementById('new_un').value;
		var emailChangeEnsurance = confirm("Вы уверены что хотите сменить почту на " + email_new + "?");
		if(emailChangeEnsurance){
			var xhr = new XMLHttpRequest();
			xhr.open('GET', 'api.php?section=users&method=changeUserEmail&email=' + email_new, true);
			xhr.setRequestHeader("Authorization", "Bearer " + window.token);
			xhr.send();
			xhr.onload = function (e) {
				if (xhr.readyState == 4 && xhr.status == 200) {
					if(xhr.responseText != ''){
						let result = JSON.parse(xhr.responseText);
						if(result.reason == 'GIVEN_EMAIL_IS_INVALID'){
							alert("Вы ввели недействительный E-Mail!");
						}
						if(result.reason == 'YOU_ARE_CURRENTLY_USING_THIS_EMAIL'){
							alert("Введённый E-Mail является вашей текущей почтой!");
						}
						if(result.result == "OK"){
							alert("Вам было отправлено письмо для подтверждения нового адреса E-Mail.");
						}
					}
				}
			}
			return true;
		}
		else{
			return false;
		}
	}	
</script>

<div class="main_module">
	<h1>Управление Аккаунтом</h1>
	<br>
	<button onclick="changeEmail()" class="button_feature_new">Сменить Почту</button>
	<div style="display: none;" id="email_changer" class="text_container">
		<br>
		<div style="margin-left: 2%;">
			<div><b>Текущая Почта:</b> <span id="email_span"></span></div>
			<br>
			<input class="input_new" name="new_un" autocomplete="off" id="new_un" placeholder="Введите Новую Почту" value="">
		</div>
		<br>
	</div>
	<button onclick="changePassword()" class="button_feature_new">Сменить Пароль</button>
	<div style="display: none;" id="password_changer" class="text_container">
		<br>
		<div style="margin-left: 2%;">
			<input type="password" class="input_new" name="password" id="password" autocomplete="current-password" placeholder="Введите Текущий Пароль"><br><br>
			<input type="password" class="input_new" autocomplete="new-password" name="new_password" id="new_password" placeholder="Введите Новый Пароль" value="">
		</div>
		<br>
	</div>
	<button onclick="show_api_management()" class="button_feature_new">Управление API</button>
	<div style="display: none;" id="api_management" class="text_container">
		<button onclick="regenerate_api()" class="button_feature_new_small">Переиздать API Ключ</button>
		<br>
		<div style="margin-left: 2%;"><b>Ваш API Ключ:</b> <span id="api"></span> &nbsp; <button onclick="showAPIKey()" class="button-7-new">Показать</button></div> 
		<br>
	</div>
	<button onclick="regenerate_slid()" class="button_feature_new">Переиздать SLID</button>
	<button onclick="totp_management()" class="button_feature_new">Управление 2FA</button>
	<button onclick="easylogin_mgmt()" class="button_feature_new">Управление EasyLogin</button>
	<br>
	
	<button class="button_submit" onclick="save_changes()" style="display: none;" id="save">Сохранить</button>

	<button onclick="logout()" class="button_cancel_new">Выйти</button>
	<br>
</div>
<script>
	var input = document.getElementById('new_un');
	var input2 = document.getElementById('new_password');

	input.oninput = function() {
		if((input.value == "" & input2.value == "") || input.value == window.email){
			document.getElementById('save').style.display = 'none';
		}
		else{
			document.getElementById('save').style.display = '';
		}
	};

	input2.oninput = function() {
		if(input2.value == "" & (input.value == "" || input.value == window.email)){
			document.getElementById('save').style.display = 'none';
		}
		else{
			document.getElementById('save').style.display = '';
		}
	};
	
	function save_changes(){
		var email = document.getElementById('new_un');
		var password = document.getElementById('new_password');
		
		if(email.value != "" && email.value != window.email){
			var rl_needed_email = submitEmailChange();
		}
		
		if(password.value != ""){
			var rl_needed_pass = submitPasswordChange();
		}
		
		if(rl_needed_email | rl_needed_pass){
			location.reload();
		}
	}
</script>