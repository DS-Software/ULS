<link rel="stylesheet" href="style.css">
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v6.1.1/css/all.css">
<link href="libs/alertify.min.css" rel="stylesheet">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<script src="libs/main.js"></script>
<script src="libs/captcha_utils.php"></script>
<script src="libs/alertify.min.js"></script>
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Авторизация</title>

<script>
	window.params = (new URL(document.location)).searchParams;
	let solid_scopes = "auth," + window.params.get("scopes");
	
	window.scopes = solid_scopes.split(",");
</script>

<div id="action_required" class="hidden-el overlap">
	<iframe class="full-screen" id="action"></iframe>
</div>

<div class="extended-form" id="main">
	<h1 class="thin-text">Авторизация</h1>
	<div class="sep-line"></div>
	<div class="full-width">
		<h2 class="thin-text no-mrg-bottom no-padding-bottom" id="project_name"></h2>
		<h2 class="thin-text no-mrg-top no-padding-top">запрашивает доступ к вашему аккаунту.</h2>
		<div class="full-width align-left">
			<div id="scope_container"></div>
		</div>
	</div>
	<div class="align-left full-width">
		<button class="button-primary" onclick="authenticate()">Продолжить</button>
		<button class="button-secondary float-right" onclick="back()">Вернуться</button>
	</div>
	<br>
</div>

<script>

	window.fault_redirect = "index.php";

	function back(){
		location.href = window.fault_redirect;
	}

	var token_xhr = new XMLHttpRequest();
	token_xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	token_xhr.send();
	token_xhr.onload = function (e) {
		let access_token = JSON.parse(token_xhr.responseText);
		switch (access_token.description) {
			case "2faVerificationRequired":
				open_login_menu();
				break;
			case "unfinishedReg":
				open_login_menu();
				break;
			case "IPVerificationRequired":
				open_login_menu();
				break;
			default:
				window.token = access_token.token;
				bootstrap();
				break;
		}
	}
	
	function open_login_menu(){
		action_required.classList.remove("hidden-el");
		main.classList.add("hidden-el");
		document.getElementById("action").src = "index.php";
		
		window.token_check = setInterval(checkaction, 500);
	}
	
	function checkaction(){
		var check_token = new XMLHttpRequest();
		check_token.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
		check_token.send();
		check_token.onload = function (e) {
			let access_token = JSON.parse(check_token.responseText);
			if(access_token.result == "OK" && access_token.token != null && access_token.description == undefined){
				window.token = access_token.token;
				bootstrap();
				action_required.classList.add("hidden-el");
				main.classList.remove("hidden-el");
				document.getElementById("action").src = "";
				clearInterval(window.token_check);
			}
		}
	}
	
	function bootstrap(){
		if(window.token == "" || window.token == undefined){
			open_login_menu();
		}
		else{
			document.getElementById("main").style.display = "";
			getProjectInfo();
			prepare_scopes();
		}
	}
	
	function prepare_scopes(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=projects&method=getScopes', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			let result = JSON.parse(xhr.responseText);
			
			if(result.result != "FAULT"){
				let scope_container = document.getElementById('scope_container');
				window.scopes_edited = [];
				window.final_scopes = "";
				window.scopes.forEach(element => {
					if(result['scopes'][element] == undefined){
						return;
					}
					if(element != ""){
						window.final_scopes += "&scopes[" + element + "]";
					}
					window.scopes_edited[element] = "true"; 
					let scope_id = "scope_" + element;
					let child = document.createElement('b');
					child.id = scope_id + "_header";
					child.textContent = result['scopes'][element]['name'];
					scope_container.appendChild(child);
					
					var content = document.createElement('p');
					content.id = scope_id + "_content";
					content.textContent = result['scopes'][element]['description'];
					content.classList.add('no-mrg-top');
					child.after(content);
				});
			}
			else{
				alertify.notify("Произошла ошибка при обращении к серверам ULS. Повторите попытку позже.", 'error', 2, function(){back()});
			}
		}
	}
	
	function getProjectInfo(){
		let project_public = window.params.get('public');
		let onFault = window.params.get('onFault');
		let sign = window.params.get('sign');
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=projects&method=getProjectInfo&public=' + project_public + "&onFault=" + onFault + "&sign=" + sign, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			let result = JSON.parse(xhr.responseText);
			
			if(result.result != "FAULT"){
				let project_name = result.project_name;
				let verified = result.verified;
				
				if(result.fault_redirect != "MALFORMED"){
					window.fault_redirect = result.fault_redirect;
				}
				
				let name_container = document.getElementById("project_name");
				name_container.textContent = project_name;
				if(verified == 1){
					let verification_mark = "<span class=\"verify_mark\">Verified</span>";
					name_container.innerHTML = name_container.innerHTML + " " + verification_mark;
				}
			}
			else{
				alertify.notify("Произошла ошибка при авторизации! Повторите вход в необходимом сервисе!", 'error', 2, function(){back()});
			}
		}
	}
	
	function authenticate(){
		if(window.scopes_edited['profile_management'] == 'true'){
			alertify.confirm("Внимание!", "При продолжении, это приложение сможет управлять вашим аккаунтом! Не давайте это разрешение приложениям, которым вы не доверяете!",
				function(){ sendrequest()},
				function(){
					console.log("[DEBUG] Cancelled Potentially Malicious Consent.")
				}
			);
		}
		else{
			sendrequest();
		}
	}
	
	function sendrequest(){
		let project_public = window.params.get('public');
		let scopes = window.final_scopes;
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=projects&method=login&public=' + project_public + scopes, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			let result = JSON.parse(xhr.responseText);
			
			if(result.redirect != "" && result.redirect != undefined){
				location.href = result.redirect;
				return;
			}
			if(result.reason == 'RATE_LIMIT_EXCEEDED'){
				window.failed_request = function(){
					accept();
				};
				callCaptcha();
				return;
			}
			alertify.notify("Произошла ошибка при авторизации! Повторите вход в необходимом сервисе!", 'error', 2, function(){back()});
		}
	}
</script>