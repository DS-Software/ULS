<link rel="stylesheet" href="../style.css">
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v6.1.1/css/all.css">
<link href="../libs/alertify.min.css" rel="stylesheet">
<link rel="shortcut icon" href="../favicon.gif" type="image/gif">
<script src="../libs/main.js"></script>
<script src="../libs/captcha_utils.php"></script>
<script src="../libs/alertify.min.js"></script>
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Создание Проекта</title>

<div class="extended-form">
	<h1 class="thin-text">Создание проекта:</h1>
	<div class="sep-line"></div>
	<div class="full-width">
		<div class="align-left icon">
			<i class="fa-solid fa-tag"></i>
		</div>
		<span class="input-placeholder">Название проекта</span>
		<input class="text-input max-width input-field-decoration" id="project_name" autocomplete="off">
	</div>
	<br>
	<div class="align-left full-width">
		<button class="button-primary" onclick="create(project_name.value)">Создать</button>
		<button class="button-secondary float-right" onclick="back()">Вернуться</button>
	</div>
	<br>
</div>

<script>
prepare_view();

var token_xhr = new XMLHttpRequest();
var xhr = new XMLHttpRequest();
token_xhr.open('GET', '../api.php?section=UNAUTH&method=getAccessToken', true);
token_xhr.send();
token_xhr.onload = function (e) {
let access_token = JSON.parse(token_xhr.responseText);
	switch (access_token.description) {
		case "2faVerificationRequired":
			location.href = "../check_user.php";
			break;
		case "unfinishedReg":
			location.href = "../home.php";
			break;
		default:
			if(access_token.result == "FAULT"){
				location.href = "../index.php";
				break;
			}
			window.token = access_token.token;
			break;
	}
}
	
function create(name){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', '../api.php?section=integration&method=createProject&name=' + encodeURI(name), true);
	xhr.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr.send();
	xhr.onload = function (e) {
		let ret = JSON.parse(xhr.responseText);
		if(ret.result == "FAULT"){
			if(ret.reason == "TOO_LONG_OR_TOO_SHORT"){
				alertify.notify("Имя проекта не должно быть короче 3 или длиннее 32 символов!", 'error', 5);
				return;
			}
			if(ret.reason == "PROJECT_CREATION_WAS_DISABLED"){
				alertify.notify("Возможность создания проектов была отключена!", 'error', 5);
				return;
			}
			if(ret.reason == "REACHED_LIMIT_OF_PROJECTS"){
				alertify.notify("Вы достигли лимита проектов!", 'error', 5);
				return;
			}
			if(ret.reason == 'RATE_LIMIT_EXCEEDED'){
				window.failed_request = function(){
					create(name);
				};
				callCaptcha();
				return;
			}
			alertify.notify("Во время создания проекта произошла непредвиденная ошибка!", 'error', 5);
		}
		else{
			back();
		}
	}
}
	
function back(){
	location.href = "index.php";
}
</script>