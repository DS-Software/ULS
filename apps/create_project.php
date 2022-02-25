<?php
	require '../config.php';
	require 'integration_config.php';
	
	if(!$enable_creation){
		header("Location: index.php?error=creation_closed");
	}
?>

<link href="../style.css" rel="stylesheet" type="text/css">
<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="../favicon.gif" type="image/gif">
<title>Аутентификация</title>

<script>
	window.login_url = "<?php echo($login_site) ?>";

	var token_xhr = new XMLHttpRequest();
	var xhr = new XMLHttpRequest();
	token_xhr.open('GET', login_url + '/api.php?section=UNAUTH&method=getAccessToken', true);
	token_xhr.send();
	token_xhr.onload = function (e) {
		let access_token = JSON.parse(token_xhr.responseText);
		if(access_token.description == "2faVerificationRequired"){
			location.href = login_url + "/2fa_check.php";
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
			location.href = login_url;
		}
	}
	
	function create(){
		let name = document.getElementById('project_name').value;
		var xhr = new XMLHttpRequest();
		xhr.open('GET', login_url + '/api.php?section=integration&method=createProject&name=' + encodeURI(name), true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			let ret = JSON.parse(xhr.responseText);
			if(ret.result == "FAULT"){
				if(ret.description == "TOO_LONG_OR_TOO_SHORT"){
					alert("Имя проекта не должно быть короче 3 или длиннее 32 символов!");
				}
				alert("Во время создания проекта произошла ошибка!");
			}
			else{
				location.href = "index.php";
			}
		}
	}
	
	function back(){
		location.href = "<?php echo($int_url) ?>";
	}
</script>

<div class="main_module noscroll">
	<h1>Создание проекта:</h1>
	<form action="javascript:void('')">
		<div align="center">
			<p>Название проекта: <input class="input" id="project_name" maxlength="32"></p>
		</div>
	</form>
	<button class="button_submit" onclick="create()" style="display: none;" id="save">Создать</button>
	<button class="button_cancel_new" onclick="back()">Вернуться</button>
	<br>
</div>

<script>
var input = document.getElementById('project_name');

input.oninput = function() {
	if(input.value == ""){
		document.getElementById('save').style.display = 'none';
	}
	else{
		document.getElementById('save').style.display = '';
	}
};
</script>