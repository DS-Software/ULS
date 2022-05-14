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

<?php
	require 'config.php';
	
	$scopes = getScopes($_GET['scopes']);
?>

<div id="action_required" class="hidden-el overlap">
	<iframe class="full-screen" id="action"></iframe>
</div>

<div class="extended-form" id="main">
	<h1 class="thin-text">Авторизация</h1>
	<div class="sep-line"></div>
	<br>
	<div class="full-width">
		<h2 class="thin-text no-mrg-bottom no-padding-bottom" id="project_name"></h2>
		<h2 class="thin-text no-mrg-top no-padding-top">запрашивает доступ к вашему аккаунту.</h2>
		<div class="full-width align-left">
			<?php
				foreach($scopes AS $key => $value){
					if($value){
						$s_name = $scope_desc[$key]['name'];
						$s_desc = $scope_desc[$key]['description'];
						
						echo("<b>" . htmlspecialchars($s_name) . "</b><br>" . htmlspecialchars($s_desc) . "<br><br>");
					}
				}
			?>
		</div>
	</div>
	<br>
	<div class="align-left full-width">
		<button class="button-primary" onclick="authenticate()">Продолжить</button>
		<button class="button-secondary float-right" onclick="back()">Вернуться</button>
	</div>
	<br>
</div>

<script>

	window.fault_redirect  = "index.php";

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
		document.getElementById("action_required").style.display = "";
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
				document.getElementById("action_required").style.display = "none";
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
		}
	}
	
	function getProjectInfo(){
		let project_public = "<?php echo(htmlspecialchars($_GET['public'])); ?>";
		let scopes = "<?php echo(htmlspecialchars($_GET['scopes'])); ?>";
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=projects&method=getProjectInfo&public=' + project_public + "&onFault=<?php echo(htmlspecialchars($_GET['onFault'])); ?>&sign=<?php echo(htmlspecialchars($_GET['sign'])); ?>", true);
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
		<?php if($scopes['profile_management']){ ?>
		alertify.confirm("Внимание!", "При продолжении, это приложение сможет управлять вашим аккаунтом! Не давайте это разрешение приложениям, которым вы не доверяете!",
			function(){ sendrequest()},
			function(){
				console.log("[DEBUG] Cancelled Potentially Malicious Consent.")
			}
		);
		<?php } 
		else { ?>
		sendrequest();
		<?php } ?>
	}
	
	function sendrequest(){
		let project_public = "<?php echo(htmlspecialchars($_GET['public'])); ?>";
		let scopes = "<?php echo(htmlspecialchars($_GET['scopes'])); ?>";
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=projects&method=login&public=' + project_public + '&scopes=' + scopes, true);
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