<?php
	require '../config.php';
	require 'integration_config.php';
?>

<link href="../style.css" rel="stylesheet" type="text/css">
<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="../favicon.gif" type="image/gif">

<link href="libs/alertify.min.css" rel="stylesheet">
<script src="libs/alertify.min.js"></script>

<title>Аутентификация</title>

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
			case "unfinishedReg":
				location.href = login_url + "/finish_register.php";
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
			if("<?php echo(htmlspecialchars($_GET['error'])); ?>" == "creation_closed"){
				alertify.notify("Вы не можете создать проект! Попробуйте позже!", 'error', 5);
				location.replace("<?php echo(htmlspecialchars($int_url)); ?>");
			}
			loadProjectInfo();
		}
	}
	
	function escapeHtml(unsafe)
	{
		return String(unsafe)
			 .replace('&', "&amp;")
			 .replace('<', "&lt;")
			 .replace('>', "&gt;")
			 .replace('"', "&quot;")
			 .replace("'", "&#039;");
	}
	
	function loadProjectInfo(){
		window.project = "<?php echo(htmlspecialchars($_GET['project_id'])) ?>";
		var xhr = new XMLHttpRequest();
		xhr.open('GET', login_url + '/api.php?section=integration&method=getProjectInfo&project=' + window.project, true);
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
			
			name_container.innerHTML = escapeHtml(project.project_name) + "&nbsp;&nbsp;<span class=\"bh\"><button onclick=\"deleteProject()\" class=\"button-7-new\">Удалить проект</button></span>";
			redirect_url.innerHTML = "<b class=\"bt_noflex\">" + escapeHtml(project.redirect_uri) + "</b>";
			if(project.redirect_uri == ""){
				redirect_url.innerHTML = "<b class=\"bt_noflex\">Не настроен!</b>";
			}
			public_key.innerHTML = "<i style=\"text-decoration: underline;\" class=\"bt_noflex\">" + escapeHtml(project.public_key) + "</b>";
			secret.innerHTML = "<i style=\"text-decoration: underline;\" class=\"bt_noflex\">" + escapeHtml(project.secret_key) + "</b>";
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
</script>

<div class="main scrollable">
	<h1>Управление Проектом</h1>
	<span class="delimiter">
		<font class="bh" id="project_name"></font>
	</span>
	<div class="project_information">
		<div id="project_current" style="width: 80%; margin-left: auto; margin-right: auto;">
			<div align="center" style="word-break: break-all;">
				<span class="bt_noflex">URL перенаправления:&nbsp;<font id="redirect_url_current"><font></span>
				<hr>
				<span class="bt_noflex">Публичный Ключ Приложения:&nbsp; <button onclick="issueNewPublic()" class="button-7-new">Переиздать</button><br><span id="public_key"></span></span>
				<hr>
				<span class="bt_noflex">Секретный Ключ Приложения:&nbsp; <button onclick="showSecret()" class="button-7-new" id="show_secret">Показать</button>&nbsp;&nbsp;<button onclick="issueNewSecret()" class="button-7-new">Переиздать</button><span id="secret_container" style="display: none;"><br><span id="secret_key"></span></span></span>
				<hr>
			</div>
		</div>
		<br>
		<button onclick="changeName()" class="button_feature_new">Сменить Имя</button>
		<div id="namechanger" style="display: none;">
			<font class="bt">Изменение названия:</font>
			<form action="javascript:void('')">
				<div align="center">
					<p>Название проекта: <input class="input" id="project_name_edit" maxlength="32"></p>
				</div>
			</form>
		</div>
		<button onclick="changeURL()" class="button_feature_new">Сменить URL перенаправления</button>
		<div id="redirect_url" style="display: none;">
			<font class="bt">Изменение URL перенаправления:</font>
			<form action="javascript:void('')">
				<div align="center">
					<p>URL перенаправления: <input class="input" id="redirect_url_edit"></p>
				</div>
			</form>
		</div>
		<button class="button_submit" onclick="save_changes()" style="display: none;" id="save">Сохранить</button>
	</div>
	<button class="button_cancel_new" onclick="back()">Вернуться</button>
</div>
<script>
	var input = document.getElementById('project_name_edit');
	var input2 = document.getElementById('redirect_url_edit');
	
	function changeName(){
		let el = document.getElementById('namechanger');
		el.style.display = (el.style.display == 'none') ? '' : 'none';
		input.value = "";
		if(input2.value == "" & input.value == ""){
			document.getElementById('save').style.display = 'none';
		}
	}
	
	function changeURL(){
		let el = document.getElementById('redirect_url');
		el.style.display = (el.style.display == 'none') ? '' : 'none';
		input2.value = "";
		if(input2.value == "" & input.value == ""){
			document.getElementById('save').style.display = 'none';
		}
	}
	
	function issueNewPublic(){
		alertify.confirm("Перевыпуск Публличного Ключа", "Вы уверены, что хотите переиздать публичный ключ проекта?",
			function(){
				var xhr = new XMLHttpRequest();
				xhr.open('GET', login_url + '/api.php?section=integration&method=issueNewPublic&project=' + window.project, true);
				xhr.setRequestHeader("Authorization", "Bearer " + window.token);
				xhr.send();
				xhr.onload = function (e) {
					location.reload();
				}
			},
			function(){
				alertify.error('Вы отменили действие!');
			}
		);
	}
	
	function issueNewSecret(){
		alertify.confirm("Перевыпуск Приватного Ключа", "Вы уверены, что хотите переиздать приватный ключ проекта?",
			function(){
				var xhr = new XMLHttpRequest();
				xhr.open('GET', login_url + '/api.php?section=integration&method=issueNewSecret&project=' + window.project, true);
				xhr.setRequestHeader("Authorization", "Bearer " + window.token);
				xhr.send();
				xhr.onload = function (e) {
					location.reload();
				}
			},
			function(){
				alertify.error('Вы отменили действие!');
			}
		);
	}


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
		let reload = false;
		if(input.value != ""){
			reload = changeProjectName(input.value);
		}
		
		if(input2.value != ""){
			reload = changeProjectRedirectURL(input2.value) | reload;
		}
		
		if(reload){
			location.reload();
		}
	}
	
	function changeProjectRedirectURL(new_url){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', login_url + '/api.php?section=integration&method=changeRedirect&project=' + window.project + "&redirect_url=" + encodeURIComponent(new_url), true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		return true;
	}
	
	function changeProjectName(new_name){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', login_url + '/api.php?section=integration&method=changeName&project=' + window.project + "&name=" + encodeURIComponent(new_name), true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		return true;
	}
	
	function deleteProject(){
		alertify.confirm("Удаление проекта", "Вы уверены, что хотите УДАЛИТЬ этот проект? Это действие нельзя отменить!",
			function(){
				var xhr = new XMLHttpRequest();
				xhr.open('GET', login_url + '/api.php?section=integration&method=delete&project=' + window.project, true);
				xhr.setRequestHeader("Authorization", "Bearer " + window.token);
				xhr.send();
				xhr.onload = function (e) {
					back();
				}
			},
			function(){
				alertify.error('Вы отменили действие!');
			}
		);
	}
</script>