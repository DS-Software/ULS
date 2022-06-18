console.log("%cWARNING!", "font-size: 5rem; color: red;");
console.log("%cDo not execute anything here unless you know what you are doing!", "font-size: 1.5rem; color: red;");
console.log("%cYou might lose your account otherwise!", "font-size: 1.5rem; color: red;");

function getCookie(name) {
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for(var i=0;i < ca.length;i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') c = c.substring(1,c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
    }
    return null;
}

function prepare_view(){
	if(getCookie("dark_mode") == 1){
		document.getElementsByTagName("body")[0].classList.add('dark');
		window.theme = "dark";
	}
	else{
		document.getElementsByTagName("body")[0].classList.remove('dark');
		window.theme = "light";
	}

	let input_fields = document.querySelectorAll('.input-field-decoration');
		
	input_fields.forEach(function(input_field){
		let input_label = input_field.previousElementSibling;
			
		input_field.addEventListener('input', function(){
			if(input_label == null){
				return;
			}
			if(input_field.value != ""){
				input_label.classList.add('placeholder-upper');
			}
			else{
				input_label.classList.remove('placeholder-upper');
			}
		});
		
		input_field.addEventListener('focus', function(){
			if(input_label == null){
				return;
			}
			
			input_label.classList.add('placeholder-upper');
		});
		
		input_field.addEventListener('blur', function(){
			if(input_label == null){
				return;
			}
			
			if(input_field.value != ""){
				return;
			}
			
			input_label.classList.remove('placeholder-upper');
		});
	});
}

function change_theme(){
	if(getCookie("dark_mode") == 1){
		document.cookie = "dark_mode=0;max-age=315360000";
		prepare_view();
		return;
	}
	else{
		document.cookie = "dark_mode=1;max-age=315360000";
		prepare_view();
		return;
	}	
}

function getLocation(href) {
    var match = href.match(/^(https?\:)\/\/(([^:\/?#]*)(?:\:([0-9]+))?)([\/]{0,1}[^?#]*)(\?[^#]*|)(#.*|)$/);
	if(match == null){
		return false;
	}

    return match && {
        href: href,
        protocol: match[1],
        host: match[2],
        hostname: match[3],
        port: match[4],
        pathname: match[5],
        search: match[6],
        hash: match[7]
    }
}