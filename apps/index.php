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

<title>Проекты</title>

<div class="extended-form">
	<h1 class="thin-text">Управление Проектами</h1>
	<div class="sep-line"></div>
	<span class="middle-text">Выберите проект, либо&nbsp;<a onclick="createNewProject()">создайте новый</a>:</span>
	<br><br>
	<div class="sep-line"></div>
	<div id="project_container" class="container">
		
	</div>
	<br>
	<div class="align-center full-width">
		<button class="button-primary" onclick="location.href = '../home.php'">Вернуться</button>
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
				bootstrap();
				break;
		}
	}
	
	function bootstrap(){
		if("<?php echo(htmlspecialchars($_GET['error'])); ?>" == "unauthorized"){
			alertify.notify("Вы не можете управлять этим проектом!", 'error', 2, function(){location.replace("<?php echo(htmlspecialchars($int_url)); ?>")});
		}
		loadUserProjects();
	}
	
	function loadUserProjects(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', '../api.php?section=integration&method=getUserProjects', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			let projects = JSON.parse(xhr.responseText);
			let container = document.getElementById("project_container");
			container.innerHTML = "";
			
			if(projects.projects.length == 0 && projects.projects.length != undefined){
				container.innerHTML = "<div class=\"hint-text margin-top-1em middle-text\">У вас нет проектов, создайте новый.</div>";
			}
			else{
				Object.values(projects.projects).forEach(
					element => {
						let id = "project" + element.project_id;
						container.innerHTML += "<div class=\"margin-top-1em middle-text a-element project-clickable\" id=\"" + id + "\"></div>";
						let handler = document.getElementById(id);
						handler.textContent = element.project_name;
						handler.dataset.id = element.project_id;
					}
				);
			}
			bind_clicks();
		}
	}

	function bind_clicks(){
		let project_clickables = document.querySelectorAll('.project-clickable');
		
		project_clickables.forEach(function(project_label){				
			project_label.addEventListener('click', function(){
				project(project_label.dataset.id);
			});
		});
	}
	
	
	function createNewProject(){
		location.href = "create_project.php";
	}
	
	function project(project_id){
		location.href = "projects.php?project_id=" + project_id;
	}
</script>