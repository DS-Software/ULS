<?php
require_once "config.php";
?>

<script>		
var token_xhr = new XMLHttpRequest();
token_xhr.open('GET', 'api.php?section=UNAUTH&method=getToken', true);
token_xhr.send();
token_xhr.onload = function (e) {
	if (token_xhr.readyState == 4 && token_xhr.status == 200) {
		let token_json = JSON.parse(token_xhr.responseText);
		if(token_json.result == "FAULT"){
			load_login_menu();
		}
		else{
			window.user_info = token_json;
			load_main_menu();
		}	
	}
};

function load_login_menu(){
	let el = document.getElementById('auth_form');
	let el2 = document.getElementById('main_form');
	el.style.display = '';
	el2.style.display = 'none';
}

function load_main_menu(){
	let el = document.getElementById('main_form');
	let el2 = document.getElementById('auth_form');
	el.style.display = '';
	el2.style.display = 'none';
	hello();
}

function hello(){
	document.getElementById("hello").textContent = "Hello, " + window.user_info.user.user_name;
}
</script>

<div id="auth_form" style="display: none;">
	<button onclick="uls_login()">Log in via ULS</button>
	<script>				
		function uls_login(){
			location.href = "<?php echo($login_url) ?>";
		}
	</script>
</div>

<div id="main_form" style="display: none;">
	<div id="hello"></div>
	<button onclick="logout()">Logout</button>
	<script>				
		function logout(){
			document.cookie = "sign=null; session=null; uls_id=null; token=null; user_id=null";
			location.reload();
		}
	</script>
</div>