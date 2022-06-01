<?php
	require_once '..' . DIRECTORY_SEPARATOR . 'config.php';
?>

<link rel="stylesheet" href="../style.css">
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v6.1.1/css/all.css">
<link href="../libs/alertify.min.css" rel="stylesheet">
<link rel="shortcut icon" href="../favicon.gif" type="image/gif">
<script src="../libs/main.js"></script>
<script src="../libs/captcha_utils.php"></script>
<script src="../libs/alertify.min.js"></script>
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Управление Проектом</title>

<div class="extended-form">
	<h1 class="thin-text">Управление Проектом</h1>
	<div class="sep-line"></div>
	<div class="full-width"><span class="middle-text" id="project_name"></span>&nbsp;&nbsp;&nbsp;<button class="button-secondary" onclick="deleteProject()">Удалить проект</button></div>
	<br>
	<div class="sep-line"></div>
	<div class="project_information">
		<div id="project_current" style="width: 80%; margin-left: auto; margin-right: auto;">
			<div align="center">
				<div class="middle-text">URL перенаправления:&nbsp;<b><span id="redirect_url_current"></span></b></div>
				<br>
				<div class="sep-line"></div>
				<div class="align-center full-width">
					<button onclick="showKeys()" class="button-primary">Управление ключами</button>
				</div>
				<br>
				<div class="hidden-el" id="keys">
					<div class="sep-line"></div>
					<div class="middle-text">Публичный Ключ Приложения:&nbsp;&nbsp;&nbsp;<button class="button-secondary" onclick="issueNewPublic()">Переиздать</button><br><span id="public_key"></span></div>
					<br>
					<div class="sep-line"></div>
					<div class="middle-text">Секретный Ключ Приложения:
					<div class="align-left full-width">
						<button onclick="showSecret()" class="button-secondary" id="show_secret">Показать</button>
						<button onclick="issueNewSecret()" class="button-secondary float-right">Переиздать</button>
					</div>
					<span id="secret_container" style="display: none;"><br><span id="secret_key"></span></span></div>
					<br>
				</div>
				<div class="sep-line"></div>
			</div>
		</div>
		<div class="align-left full-width">
			<button onclick="openName()" class="button-secondary">Сменить Название</button>
			<button onclick="openURL()" class="button-secondary float-right">Сменить URL перенаправления</button>
		</div>
		<div id="change_name" class="hidden-el">
			<p class="middle-text">Изменение названия:</p>
			<div class="full-width">
				<div class="align-left icon">
					<i class="fa-solid fa-tag"></i>
				</div>
				<span class="input-placeholder">Название проекта</span>
				<input class="text-input max-width input-field-decoration" id="new_project_name" autocomplete="off" maxlength="32">
				<br><br>
				<div class="align-center full-width">
					<button onclick="changeProjectName(new_project_name.value)" class="button-primary">Сменить Название</button>
				</div>
			</div>
		</div>
		<div id="change_url" class="hidden-el">
			<p class="middle-text">Изменение URL перенаправления:</p>
			<div class="full-width">
				<div class="align-left icon">
					<i class="fa-solid fa-link"></i>
				</div>
				<span class="input-placeholder">URL Перенаправления</span>
				<input class="text-input max-width input-field-decoration" id="new_redirect_url" autocomplete="off">
				<br><br>
				<div class="align-center full-width">
					<button onclick="changeProjectRedirectURL(new_redirect_url.value)" class="button-primary">Сменить URL</button>
				</div>
			</div>
		</div>
	</div>
	<br>
	<div class="sep-line"></div>
	<div class="align-center full-width">
		<button class="button-primary max-width" onclick="back()">Вернуться</button>
	</div>
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
				back();
				break;
			}
			window.token = access_token.token;
			loadProjectInfo();
			break;
	}
}
	
function loadProjectInfo(){
	window.project = "<?php echo(htmlspecialchars($_GET['project_id'])) ?>";
	var xhr = new XMLHttpRequest();
	xhr.open('GET', '../api.php?section=integration&method=getProjectInfo&project=' + window.project, true);
	xhr.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr.send();
	xhr.onload = function (e) {
		let project = JSON.parse(xhr.responseText);
		let name_container = document.getElementById("project_name");
		let redirect_url = document.getElementById("redirect_url_current");
		let public_key = document.getElementById("public_key");
		let secret = document.getElementById("secret_key");
			
		if(project.result == "FAULT"){
			location.href = "<?php echo(htmlspecialchars($int_url)) ?>?error=unauthorized";
		}
			
		name_container.textContent = project.project_name;
		redirect_url.textContent = project.redirect_uri;
		if(project.redirect_uri == ""){
			redirect_url.innerHTML = "<b>Не настроен!</b>";
		}
		public_key.innerHTML = "<i>" + project.public_key + "</i>";
		secret.innerHTML = "<i>" + project.secret_key + "</i>";
	}
}
	
function back(){
	location.href = "<?php echo(htmlspecialchars($int_url)) ?>";
}
	
function showSecret(){
	let el = document.getElementById('secret_container');
	let el2 = document.getElementById('show_secret');
	el.style.display = (el.style.display == 'none') ? '' : 'none';
	el2.textContent = (el.style.display == 'none') ? 'Показать' : 'Скрыть';
}

function issueNewPublic(){
	alertify.confirm("Перевыпуск Публичного Ключа", "Вы уверены, что хотите переиздать публичный ключ проекта?",
		function(){
			var xhr = new XMLHttpRequest();
			xhr.open('GET', '../api.php?section=integration&method=issueNewPublic&project=' + window.project, true);
			xhr.setRequestHeader("Authorization", "Bearer " + window.token);
			xhr.send();
			xhr.onload = function (e) {
				location.reload();
			}
		},
		function(){
			console.log("[DEBUG] Cancelled action");
		}
	);
}
	
function issueNewSecret(){
	alertify.confirm("Перевыпуск Приватного Ключа", "Вы уверены, что хотите переиздать приватный ключ проекта?",
		function(){
			var xhr = new XMLHttpRequest();
			xhr.open('GET', '../api.php?section=integration&method=issueNewSecret&project=' + window.project, true);
			xhr.setRequestHeader("Authorization", "Bearer " + window.token);
			xhr.send();
			xhr.onload = function (e) {
				location.reload();
			}
		},
		function(){
			console.log("[DEBUG] Cancelled action");
		}
	);
}

function openName(){
	let el = document.getElementById('change_name');
	if(el.classList.contains('hidden-el')){
		el.classList.remove('hidden-el');
		document.getElementById('keys').classList.add('hidden-el');
		document.getElementById('change_url').classList.add('hidden-el');
	}
	else{
		el.classList.add('hidden-el');
	}
}

function openURL(){
	let el = document.getElementById('change_url');
	if(el.classList.contains('hidden-el')){
		el.classList.remove('hidden-el');
		document.getElementById('keys').classList.add('hidden-el');
		document.getElementById('change_name').classList.add('hidden-el');
	}
	else{
		el.classList.add('hidden-el');
	}
}


function showKeys(){
	let el = document.getElementById('keys');
	if(el.classList.contains('hidden-el')){
		el.classList.remove('hidden-el');
		document.getElementById('change_name').classList.add('hidden-el');
		document.getElementById('change_url').classList.add('hidden-el');
	}
	else{
		el.classList.add('hidden-el');
	}
}
	
function changeProjectRedirectURL(new_url){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', '../api.php?section=integration&method=changeRedirect&project=' + window.project + "&redirect_url=" + encodeURIComponent(new_url), true);
	xhr.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr.send();
	xhr.onload = function (e) {
		let result = JSON.parse(xhr.responseText);
		if(result.result == "OK"){
			loadProjectInfo();
			document.getElementById('change_url').classList.add('hidden-el');
		}
	}
}
	
function changeProjectName(new_name){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', '../api.php?section=integration&method=changeName&project=' + window.project + "&name=" + encodeURIComponent(new_name), true);
	xhr.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr.send();
	xhr.onload = function (e) {
		let result = JSON.parse(xhr.responseText);
		if(result.reason == "TOO_LONG_OR_TOO_SHORT"){
			alertify.notify('Выбранное имя слишком длинное / короткое.', 'error', 500);
			return;
		}
		if(result.result == "OK"){
			loadProjectInfo();
			document.getElementById('change_name').classList.add('hidden-el');
		}
	}
}
	
function deleteProject(){
	alertify.confirm("Удаление проекта", "Вы уверены, что хотите УДАЛИТЬ этот проект? Это действие нельзя отменить!",
		function(){
			var xhr = new XMLHttpRequest();
			xhr.open('GET', '../api.php?section=integration&method=delete&project=' + window.project, true);
			xhr.setRequestHeader("Authorization", "Bearer " + window.token);
			xhr.send();
			xhr.onload = function (e) {
				back();
			}
		},
		function(){
			console.log("[DEBUG] Cancelled action");
		}
	);
}
</script>