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
			if("<?php echo($_COOKIE['redirect']) ?>" != ""){
				location.href = "service_redirect.php";
			}
		}
	}
	
	function getUserEmail(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=users&method=getCurrentEmail&access_token=' + window.token, true);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				let el = document.getElementById('email_span');
				
				el.innerHTML = result.email;
			}
		}
	}
	
	function logout(){
		xhr.open('GET', 'api.php?section=users&method=logout&access_token=' + window.token, true);
		xhr.send();
		xhr.onload = function (e) {
			location.reload();
		}
	}
	
	function regenerate_api(){
		var confirmed = confirm("Этим действием вы перевыпустите ваш API ключ! Это обнулит ваш предыдущий API ключ!");
		if(confirmed){
			xhr.open('GET', 'api.php?section=users&method=regenerate_api_key&access_token=' + window.token, true);
			xhr.send();
			xhr.onload = function (e) {
				location.reload();
			}
		}
	}
	
	function regenerate_slid(){
		var confirmed = confirm("Этим действием вы перевыпустите ID вашей сессии! Это приведёт к принудительному закрытию всех сеансов!");
		if(confirmed){
			xhr.open('GET', 'api.php?section=users&method=regenerate_slid&access_token=' + window.token, true);
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
	
	var input = document.getElementById('email_change');
	var input2 = document.getElementById('password_change');
	
	function changePassword(){
		let el = document.getElementById('password_changer');
		el.style.display = (el.style.display == 'none') ? '' : 'none';
		input2.value = "";
		if(input.value == ""){
			document.getElementById('save').style.display = 'none';
		}
	}
	
	function submitPasswordChange(){
		var password_new = document.getElementById('password_change').value;
		var passwordChangeEnsurance = confirm("Вы уверены что хотите сменить пароль?");
		if(passwordChangeEnsurance){
			var xhr = new XMLHttpRequest();
			xhr.open('GET', 'api.php?section=users&method=changeUserPassword&access_token=' + window.token + '&password=' + password_new, true);
			xhr.send();
			return true;
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
		var email_new = document.getElementById('email_change').value;
		var emailChangeEnsurance = confirm("Вы уверены что хотите сменить почту на " + email_new + "?");
		if(emailChangeEnsurance){
			var xhr = new XMLHttpRequest();
			xhr.open('GET', 'api.php?section=users&method=changeUserEmail&access_token=' + window.token + '&email=' + email_new, true);
			xhr.send();
			xhr.onload = function (e) {
				if (xhr.readyState == 4 && xhr.status == 200) {
					if(xhr.responseText != ''){
						if(xhr.responseText == '{"result":"FAULT","reason":"GIVEN_EMAIL_WAS_REGISTERED"}'){
							alert("Этот E-Mail используется другим пользователем!");
						}
						if(xhr.responseText == '{"result":"FAULT","reason":"GIVEN_EMAIL_IS_INVALID"}'){
							alert("Вы ввели недействительный E-Mail!");
						}
						if(xhr.responseText == '{"result":"FAULT","reason":"YOU_ARE_CURRENTLY_USING_THIS_EMAIL"}'){
							alert("Введённый E-Mail является вашей текущей почтой!");
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
			<input class="input_new" name="email" id="email_change" placeholder="Введите Новую Почту">
		</div>
		<br>
	</div>
	<button onclick="changePassword()" class="button_feature_new">Сменить Пароль</button>
	<div style="display: none;" id="password_changer" class="text_container">
		<br>
		<div style="margin-left: 2%;">
			<input class="input_new" name="password" id="password_change" placeholder="Введите Новый Пароль">
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
	var input = document.getElementById('email_change');
	var input2 = document.getElementById('password_change');

	input.oninput = function() {
		if(input.value == "" & input2.value == ""){
			document.getElementById('save').style.display = 'none';
		}
		else{
			document.getElementById('save').style.display = '';
		}
	};

	input2.oninput = function() {
		if(input2.value == "" & input.value == ""){
			document.getElementById('save').style.display = 'none';
		}
		else{
			document.getElementById('save').style.display = '';
		}
	};
	
	function save_changes(){
		var email = document.getElementById('email_change');
		var password = document.getElementById('password_change');
		
		if(email.value != ""){
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