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
		else{
			if("<?php echo($_GET['error']); ?>" == "creation_closed"){
				alert("Вы не можете создать проект! Попробуйте позже!");
				location.replace("<?php echo($int_url); ?>");
			}
			if("<?php echo($_GET['error']); ?>" == "unauthorized"){
				alert("Вы не можете управлять этим проектом!");
				location.replace("<?php echo($int_url); ?>");
			}
			loadUserProjects();
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
	
	function loadUserProjects(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', login_url + '/api.php?section=integration&method=getUserProjects', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			let projects = JSON.parse(xhr.responseText);
			let container = document.getElementById("project_container");
			
			if(projects.projects == null){
				container.innerHTML = "<font color=\"gray\" class=\"bt\">У вас нет проектов, создайте новый.</font>";
			}
			else{
				Object.values(projects.projects).forEach(
					element => {
						container.innerHTML += "<span style=\"text-decoration: underline;cursor: pointer;\" class=\"bt\" onclick=\"project(" + escapeHtml(element.project_id) + ")\">" + escapeHtml(element.project_name) + "</span><br>";
					}
				);
			}
		}
	}
	
	function createNewProject(){
		location.href = "create_project.php";
	}
	
	function project(project_id){
		location.href = "projects.php?project_id=" + project_id;
	}
</script>

<div class="main noscroll">
	<h1>Управление Проектами</h1>
	<span class="delimiter">
		<font class="bh">Выберите проект, либо&nbsp;<a class="bh" style="text-decoration: underline;cursor: pointer;font-weight: bold;" onclick="createNewProject()">создайте новый</a>:</font>
	</span>
	<div id="project_container" class="scrollable container">
		
	</div>
</div>