<link rel="stylesheet" href="style.css">
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v6.1.1/css/all.css">
<link href="libs/alertify.min.css" rel="stylesheet">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<script src="libs/main.js"></script>
<script src="libs/captcha_utils.php"></script>
<script src="libs/alertify.min.js"></script>
<script src="libs/qr_reader.min.js" async defer></script>
<meta name="viewport" content="width=device-width, initial-scale=1">

<?php
require_once "config.php";
?>

<title>Управление Аккаунтом</title>

<div class="sidebar align-center" id="sidebar">
	<h1 class="thin-text" onclick="close_sidebar()">Профиль</h1>
	<div class="menu-item padding-1em align-left" onclick="choose_tab('main')">
		<i class="fa-solid fa-house content-icon"></i>
		Главная
	</div>
	<div class="menu-item padding-1em align-left" onclick="choose_tab('personal_info')">
		<i class="fa-solid fa-file-lines content-icon"></i>
		Личные Данные
	</div>
	<div class="menu-item padding-1em align-left" onclick="choose_tab('security')">
		<i class="fa-solid fa-shield-halved content-icon"></i>
		Безопасность
	</div>
	<div class="menu-item padding-1em align-left" onclick="choose_tab('api')">
		<i class="fa-solid fa-code content-icon"></i>
		API
	</div>
	<div class="menu-item padding-1em align-left" onclick="choose_tab('easylogin')">
		<i class="fa-solid fa-barcode content-icon"></i>
		Беспарольный Вход
	</div>
	<div class="menu-item padding-1em align-left" onclick="integrations()">
		<i class="fa-solid fa-link content-icon"></i>
		Проекты
	</div>
	<div class="menu-item padding-1em align-left" onclick="change_theme()">
		<i class="fa-solid fa-palette content-icon"></i>
		Тема
	</div>
	<div class="hidden-el menu-item padding-1em align-left" onclick="choose_tab('admin')" id="admin_item">
		<i class="fa-solid fa-gear content-icon"></i>
		Управление
	</div>
	<div class="menu-item padding-1em align-left" onclick="logout()">
		<i class="fa-solid fa-arrow-right content-icon"></i>
		Выйти
	</div>
</div>

<div class="content-body">
	<div class="header">
		<span class="thin-text big-text" onclick="open_sidebar()"><?php echo(htmlspecialchars($email_info['$project_name'])) ?></span>
	</div>
	<div class="content" id="sel_tab">
		
	</div>
</div>

<script>
function open_sidebar(){
	sidebar.style.display = "block";
}
function close_sidebar(){
	sidebar.style.display = "";
}
</script>

<div class="hidden-el" id="samples">
	<div id="main">
		<div class="user-overview">
			<span id="user_name" class="middle-text"></span><br>
			<span id="email"></span>
		</div>
		<h2 class="thin-text">Управление Аккаунтом</h2>
		<div class="data-container">
			<span class="middle-text">
				<i class="fa-solid fa-envelope content-icon"></i>
				<span id="email_changer"></span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="choose_tab('email_change_form')">Сменить Почту</button><br><br>
			<span class="hint-text">Ваша основная почта.<br>Используется для восстановления доступа и подтверждения входа.</span>
		<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-key content-icon"></i>
				Пароль
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="choose_tab('password_change_form')">Сменить Пароль</button><br><br>
			<span class="hint-text">Строка, используемая для входа в аккаунт.</span>
		</div>
		<br>
	</div>
	<div id="personal_info">
		<div class="data-prompt align-center">
			<br>
			<h1 class="thin-text">Личная Информация</h1>
			<div class="full-width">
				<div class="align-left icon">
					<i class="fa-solid fa-user-tag"></i>
				</div>
				<span class="input-placeholder">Tag пользователя</span>
				<input class="text-input max-width input-field-decoration" id="user_tag" autocomplete="off">
				<br><br>
				<div class="align-left icon">
					<i class="fa-solid fa-user-pen"></i>
				</div>
				<span class="input-placeholder">Ваше Имя</span>
				<input class="text-input max-width input-field-decoration" id="user_name" autocomplete="off">
				<br><br>
				<div class="align-left icon">
					<i class="fa-solid fa-user-plus"></i>
				</div>
				<span class="input-placeholder">Ваша Фамилия</span>
				<input class="text-input max-width input-field-decoration" id="user_surname" autocomplete="off">
				<br><br>
				<div class="align-left icon">
					<i class="fa-solid fa-birthday-cake"></i>
				</div>
				<span class="input-placeholder placeholder-upper">День Рождения</span>
				<input class="text-input max-width" type="date" id="user_birthday" min="1900-01-01" required><br><br>
				<div class="align-сenter full-width">
					<button class="button-primary" onclick="update_user_info(user_tag.value, user_name.value, user_surname.value, user_birthday.valueAsNumber)">Сохранить</button>
				</div>
				<br><br><br>
			</div>
		</div>
		<br>
	</div>
	<div id="security">
		<div>
			<h2 class="thin-text">Вход и Авторизация</h2>
			<div class="data-container">
				<span class="middle-text">
					<i class="fa-solid fa-user-shield content-icon"></i>
					<span>Двухфакторная Аутентификация</span>
				</span>&nbsp;&nbsp;&nbsp;
				<button id="totp_state" class="button-primary float-right" onclick="manage_totp()">Включить</button><br><br>
				<span class="hint-text">Подтверждение входа посредством получения кодов из<br>приложения-генератора кодов.</span>
			<br><br>
				<span class="middle-text">
					<i class="fa-solid fa-envelope-circle-check content-icon"></i>
					Подтверждение по почте
				</span>&nbsp;&nbsp;&nbsp;
				<button id="email_check" class="button-primary float-right" onclick="manage_email()">Включить</button><br><br>
				<span class="hint-text">Подтверждение входа посредством получения кодов из<br>сообщения, отправленного на основную почту.</span>
			<br><br>
				<span class="middle-text">
					<i class="fa-solid fa-barcode content-icon"></i>
					Беспарольный Вход
				</span>&nbsp;&nbsp;&nbsp;
				<button id="easylogin_state" class="button-primary float-right" onclick="manage_easylogin()">Включить</button><br><br>
				<span class="hint-text">Вход без пароля посредством подтверждения<br>входа с авторизированного устройства.</span>
			<br><br>
				<span class="middle-text">
					<i class="fa-solid fa-circle-xmark content-icon"></i>
					Выход из всех сессий
				</span>&nbsp;&nbsp;&nbsp;
				<button class="button-primary float-right" onclick="regenerateSLID()">Выйти</button><br><br>
				<span class="hint-text">Выход из всех сессий, в которые был<br>произведён вход с этого аккаунта.</span>
			</div>
			<br>
		</div>
	</div>
	<div id="api">
		<div class="user-overview">
			<span class="middle-text">
				Ваш API Ключ Доступа Пользователя:
			</span>
			<br><br>
			<span id="user_api"></span>
			<br><br>
			<button class="button-primary" id="show_api_btn" onclick="show_api()">Показать Ключ</button>
			<br>
		</div>
		<h2 class="thin-text">Управление Ключами</h2>
		<div class="data-container">
			<span class="middle-text">
				<i class="fa-solid fa-arrows-rotate content-icon"></i>
				<span>Переиздать ключи</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="regenerateAPI()">Переиздать</button><br><br>
			<span class="hint-text">Переиздание ключей приведёт к аннулированию предыдущих<br>API ключей.</span>
		</div>
		<br>
	</div>
	<div id="easylogin">
		<div class="data-prompt align-center">
			<br>
			<h1 class="thin-text">Беспарольный Вход</h1>
			<div id="QR_Container"><div id="reader"></div></div>
			<br>
			<div class="align-сenter full-width">
				<button class="button-primary" onclick="choose_tab('main')">Вернуться</button>
			</div>
			<br>
		</div>
		<br>
	</div>
	<div id="admin">
		<h2 class="thin-text">Статистика Платформы</h2>
		
		<div class="data-container">
			<span class="middle-text">
				<i class="fa-solid fa-server content-icon"></i>
				<span>Количество Запросов:</span>
			</span>&nbsp;&nbsp;&nbsp;<span class="big-text" id="requests"></span>
			<br>
			<span class="hint-text">Количество запросов к методам, ограниченным лимитами.</span>
			<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-ticket content-icon"></i>
				<span>Количество Сессий EasyLogin:</span>
			</span>&nbsp;&nbsp;&nbsp;<span class="big-text" id="sessions"></span>
			<br>
			<span class="hint-text">Количество активных сессий EasyLogin созданных для беспарольного входа.</span>
			<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-user content-icon"></i>
				<span>Количество Пользователей:</span>
			</span>&nbsp;&nbsp;&nbsp;<span class="big-text" id="users"></span>
			<br>
			<span class="hint-text">Количество активных аккаунтов созданных на этой платформе.</span>
			<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-chain content-icon"></i>
				<span>Количество Проектов:</span>
			</span>&nbsp;&nbsp;&nbsp;<span class="big-text" id="projects"></span>
			<br>
			<span class="hint-text">Количество активных сторонних интеграций.</span>
		</div>
		<br>
		<h2 class="thin-text">Управление Платформой</h2>
		<div class="data-container">
			<span class="middle-text">
				<i class="fa-solid fa-eraser content-icon"></i>
				<span>Очистить запросы</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="purgeRequests()">Очистить</button><br><br>
			<span class="hint-text">Очистит таблицу запросов, что приведёт к обнулению лимитов API.</span>
			<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-eraser content-icon"></i>
				<span>Очистить сессии EasyLogin</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="purgeSessions()">Очистить</button><br><br>
			<span class="hint-text">Очистит таблицу сессий EasyLogin, что приведёт к аннулированию предыдущих сессий.</span>
			<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-gear content-icon"></i>
				<span>Управление Проектом</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="choose_tab('admin_project')">Продолжить</button><br><br>
			<span class="hint-text">Управление проектом от имени администратора.</span>
			<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-user content-icon"></i>
				<span>Управление Пользователем</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="choose_tab('admin_user')">Продолжить</button><br><br>
			<span class="hint-text">Управление аккаунтом пользователя от имени администратора.</span>
		</div>
		<br>
	</div>
	
	<div id="admin_user">
		<div class="data-prompt align-center">
			<br>
			<h1 class="thin-text">Управление Пользователем</h1>
			<div class="full-width">
				<div class="align-left icon">
					<i class="fa-solid fa-key"></i>
				</div>
				<span class="input-placeholder">EMail Пользователя или ID</span>
				<input class="text-input max-width input-field-decoration" id="user_email" autocomplete="off">
			</div>
			<div class="align-left full-width">
				<button class="button-primary" onclick="admin_user_info(user_email.value)">Продолжить</button>
				<button class="button-primary float-right" onclick="choose_tab('admin')">Вернуться</button>
			</div>
			<br><br>
		</div>
		<br>
	</div>
	<div id="admin_user_actions">
		<div class="user-overview">
			<span id="user_name" class="middle-text"></span><br>
			<span id="admin_email"></span><br>
			<span id="admin_id"></span>
		</div>
		<h2 class="thin-text">Управление Пользователем</h2>
		<div class="data-container">
			<span class="middle-text">
				<i class="fa-solid fa-circle-check content-icon"></i>
				<span>Подтвердить Пользователя</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="admin_verify_user()" id="verify_user">Подтвердить</button><br><br>
			<span class="hint-text">Подтверждает пользователя.<br>Пользователь получит статус Verified и дополнительные права.</span>
		<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-redo content-icon"></i>
				<span>Сбросить Пароль</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="admin_reset_user_password()">Выполнить</button><br><br>
			<span class="hint-text">Сбрасывает пароль пользователя.<br>Пользователь сможет войти только после восстановления пароля.</span>
		<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-redo content-icon"></i>
				<span>Сбросить IP Адрес</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="admin_reset_user_ip()">Выполнить</button><br><br>
			<span class="hint-text">Сбрасывает последний IP пользователя.<br>Пользователь сможет войти только после прохождения проверки по почте.</span>
		<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-redo content-icon"></i>
				<span>Сбросить SLID</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="admin_reset_user_slid()">Выполнить</button><br><br>
			<span class="hint-text">Сбрасывает SLID пользователя.<br>Все сеансы пользователя станут недействительными.</span>
		<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-ban content-icon"></i>
				<span>Заблокировать Аккаунт</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="admin_ban_user()" id="ban_user">Заблокировать</button><br><br>
			<span class="hint-text">Аккаунт пользователя будет заблокирован.<br>Пользователь не сможет производить операций с аккаунтом и входить при помощи ULS.<span id="current_ban_reason" class="hidden-el"><br>Причина Блокировки: </span></span>
		<br>
			<h2 class="thin-text">Функции Безопасности</h2>
			<div class="align-center">
				<button class="button-primary" id="sec_totp">2FA (Enabled)</button>&nbsp;
				<button class="button-primary" id="sec_easylogin">EasyLogin (Enabled)</button>&nbsp;
				<button class="button-primary" id="sec_emailcheck">EMail Check (Enabled)</button>
			</div>
		<br>
		<div class="full-width">
			<button class="button-primary max-width" onclick="choose_tab('admin_user')">Вернуться</button>
		</div>
		</div>
		<br><br>
	</div>	
	<div id="admin_project">
		<div class="data-prompt align-center">
			<br>
			<h1 class="thin-text">Управление Проектом</h1>
			<div class="full-width">
				<div class="align-left icon">
					<i class="fa-solid fa-key"></i>
				</div>
				<span class="input-placeholder">ID Проекта</span>
				<input class="text-input max-width input-field-decoration" id="project_id" autocomplete="off">
			</div>
			<div class="align-left full-width">
				<button class="button-primary" onclick="admin_project_info(project_id.value)">Продолжить</button>
				<button class="button-primary float-right" onclick="choose_tab('admin')">Вернуться</button>
			</div>
			<br><br>
		</div>
		<br>
	</div>
	<div id="admin_project_actions">
		<div class="user-overview">
			<span id="project_name" class="middle-text"></span><br>
			<span id="redirect_uri"></span><br>
			<span id="owner_id"></span>
		</div>
		<h2 class="thin-text">Управление Проектом</h2>
		<div class="data-container">
			<span class="middle-text">
				<i class="fa-solid fa-trash-can content-icon"></i>
				<span>Удалить Проект</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="admin_delete_project()" id="delete_project">Удалить</button><br><br>
			<span class="hint-text">Окончательно удаляет проект.<br>Доступно только после удаления проекта пользователем.</span>
		<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-trash-can-arrow-up content-icon"></i>
				<span>Восстановить Проект</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="admin_restore_project()" id="restore_project">Восстановить</button><br><br>
			<span class="hint-text">Восстанавливает проект.<br>Доступно только после удаления проекта пользователем.</span>
		<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-circle-check content-icon"></i>
				<span>Подтвердить Проект</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="admin_verify_project()" id="verify_project">Подтвердить</button><br><br>
			<span class="hint-text">Подтверждает проект.<br>Проект получит статус Verified и дополнительные права доступа.</span>
		<br><br>
			<span class="middle-text">
				<i class="fa-solid fa-redo content-icon"></i>
				<span>Сбросить URL Перенаправления</span>
			</span>&nbsp;&nbsp;&nbsp;
			<button class="button-primary float-right" onclick="admin_reset_project()" id="reset_project">Сбросить</button><br><br>
			<span class="hint-text">Сбрасывает URL Перенаправления Проекта<br>Используется для приостановки деятельности проекта.</span>
		<br>
		<div class="full-width">
			<button class="button-primary max-width" onclick="choose_tab('admin_project')">Вернуться</button>
		</div>
		</div>
		<br><br>
	</div>
	<div id="email_change_form">
		<div class="data-prompt align-center">
			<br>
			<h1 class="thin-text">Смена Почты</h1>
			<div class="full-width">
				<div class="align-left icon">
					<i class="fa-solid fa-envelope"></i>
				</div>
				<span class="input-placeholder">Новый EMail</span>
				<input class="text-input max-width input-field-decoration" id="email_update" autocomplete="on">
				<br><br>
				<div class="align-left full-width">
					<button class="button-primary" onclick="send_change_email(email_update.value)">Сменить</button>
					<button class="button-secondary float-right" onclick="choose_tab('main')">Вернуться</button>
				</div>
				<br>
			</div>
		</div>
		<br>
	</div>
	<div id="password_change_form">
		<div class="data-prompt align-center">
			<br>
			<h1 class="thin-text">Смена Пароля</h1>
			<div class="full-width">
				<input class="text-input max-width hidden-el input-field-decoration" type="email" id="email" autocomplete="on">
				<div class="align-left icon">
					<i class="fa-solid fa-key"></i>
				</div>
				<span class="input-placeholder">Старый Пароль</span>
				<input class="text-input max-width input-field-decoration" type="password" id="password" autocomplete="on">
				<br><br>
				<div class="align-left icon">
					<i class="fa-solid fa-key"></i>
				</div>
				<span class="input-placeholder">Новый Пароль</span>
				<input class="text-input max-width input-field-decoration" id="new_password">
				<br><br>
				<div class="align-left full-width">
					<button class="button-primary" onclick="change_password(password.value, new_password.value)">Сменить</button>
					<button class="button-secondary float-right" onclick="choose_tab('main')">Вернуться</button>
				</div>
				<div class="full-width">
					<button class="button-secondary" onclick="genNewPwd()">Создать пароль</button>
				</div>
				<br>
			</div>
		</div>
		<br>
	</div>
	<div id="totp_enable_form">
		<div class="data-prompt align-center">
			<br>
			<h1 class="thin-text">Включение 2FA</h1>
			<div class="full-width">
				<h2 class="thin-text">Отсканируйте этот QR Код, либо введите секретный ключ:</h2>
				<h3 class="thin-text" id="otp_secret"></h3>
				<img src="" id="TOTP_QR">
				
				<h2 class="thin-text">Введите OTP для подтверждения:</h2>
				<div class="align-left icon">
					<i class="fa-solid fa-lock"></i>
				</div>
				<span class="input-placeholder">Код 2FA</span>
				<input class="text-input max-width input-field-decoration" type="number" id="totp_otp">
				<br><br>
				<div class="align-left full-width">
					<button class="button-primary" onclick="proceed_totp_enable(totp_otp.value)">Продолжить</button>
					<button class="button-secondary float-right" onclick="choose_tab('security')">Вернуться</button>
				</div>
			</div>
			<br>
		</div>
		<br>
	</div>
	<div id="totp_completed_form">
		<div class="data-prompt align-center">
			<br>
			<h1 class="thin-text">Управление 2FA</h1>
			<div class="full-width">
				<h2 class="thin-text">Вы успешно включили 2FA!</h2>
				<h3 class="thin-text">Пожалуйста, сохраните или запишите ключ отключения 2FA:</h3>
				<h2 class="thin-text" id="disable_code"></h2>
				
				<h3 class="thin-text">Этот ключ позволит вам отключить 2FA при утере устройства-генератора кодов. Если у вас уже был код отключения 2FA, он недействителен. Используйте вместо него ЭТОТ код.</h3>
				
				<div class="align-center full-width">
					<button class="button-primary" onclick="checkAPIToken()">Завершить</button>
				</div>
			</div>
			<br><br>
		</div>
		<br>
	</div>
	<div id="totp_disable_form">
		<div class="data-prompt align-center">
			<br>
			<h1 class="thin-text">Отключение 2FA</h1>
			<div class="full-width">
				<h2 class="thin-text">Введите OTP для продолжения:</h2>
				<div class="align-left icon">
					<i class="fa-solid fa-lock"></i>
				</div>
				<span class="input-placeholder">Код 2FA</span>
				<input class="text-input max-width input-field-decoration" type="number" id="totp_otp">
				<br><br>
				<div class="align-left full-width">
					<button class="button-primary" onclick="proceed_totp_disable(totp_otp.value)">Продолжить</button>
					<button class="button-secondary float-right" onclick="choose_tab('security')">Вернуться</button>
				</div>
			</div>
			<br>
		</div>
		<br>
	</div>
</div>

<script>
prepare_view();
checkAPIToken();
conflict_preventer();

window.admin_initalized = false;
window.is_admin = false;

window.onpopstate = function(event) {
	window.state_updated = true;
	choose_tab(event.state.tab);
};

function checkAPIToken(){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	xhr.send();
	xhr.onload = function (e) {
		let access_token = JSON.parse(xhr.responseText);
		switch (access_token.description) {
			case "2faVerificationRequired":
				location.href = "check_user.php";
				break;
			case "unfinishedReg":
				window.tab_locked = true;
				window.token = access_token.token;
				choose_tab('personal_info');
				break;
			case "IPVerificationRequired":
				location.href = "check_user.php";
				break;
			default:
				if(access_token.token == "" || access_token.result == "FAULT"){
					location.href = "index.php";
				}
				else{
					let params = (new URL(document.location)).searchParams;
					let tab = params.get("tab");
					window.tab_locked = false;
					window.token = access_token.token;
					if(tab == "main" 
					|| tab == "personal_info"
					|| tab == "security"
					|| tab == "api"
					|| tab == "easylogin"){
						choose_tab(tab);
						if(!(tab == "main" || tab == "personal_info")){
							load_admin();
						}
					}
					else{
						choose_tab("main");
					}
				}
				break;
		}
	}
}

function conflict_preventer(){
	var elements = document.getElementById("samples").getElementsByTagName("*");
	for (let element of elements){
		let html = element.innerHTML;
		element.innerHTML = "";
		element.textContent = html;
	}
}

function choose_tab(tab){
	close_sidebar();
	if(window.tab_locked && tab != "personal_info"){
		return;
	}
	if(window.current_tab == tab){
		return;
	}
	if(window.current_tab == "easylogin"){
		try{
			window.html5QrCode.stop();
		}
		catch(err){ 
			console.log(err);
		}
	}
	
	window.current_tab = tab;
	
	let update_state = false;
	
	if(tab == "main"){
		sel_tab.innerHTML = main.textContent;
		prepare_main();
		update_state = true;
	}
	if(tab == "personal_info"){
		sel_tab.innerHTML = personal_info.textContent;
		loadUserInfo();
		update_state = true;
	}
	if(tab == "security"){
		sel_tab.innerHTML = security.textContent;
		getSecurityInfo();
		update_state = true;
	}
	if(tab == "api"){
		sel_tab.innerHTML = api.textContent;
		update_state = true;
	}
	if(tab == "easylogin"){
		sel_tab.innerHTML = easylogin.textContent;
		initQRReader();
		update_state = true;
	}
	if(tab == "admin" && window.is_admin){
		sel_tab.innerHTML = admin.textContent;
		load_admin_stats();
		update_state = true;
	}
	
	if(update_state){
		if(!window.state_updated){
			history.pushState({tab: tab}, "", "?tab=" + tab);
		}
		else{
			window.state_updated = false;
		}
	}
	
	/* Internal Forms */
	if(tab == "email_change_form"){
		sel_tab.innerHTML = email_change_form.textContent;
	}
	if(tab == "password_change_form"){
		sel_tab.innerHTML = password_change_form.textContent;
	}
	if(tab == "totp_enable_form"){
		sel_tab.innerHTML = totp_enable_form.textContent;
		prepare_totp_enable();
	}
	if(tab == "totp_completed_form"){
		sel_tab.innerHTML = totp_completed_form.textContent;
	}
	if(tab == "totp_disable_form"){
		sel_tab.innerHTML = totp_disable_form.textContent;
	}
	if(tab == "admin_project" && window.is_admin){
		sel_tab.innerHTML = admin_project.textContent;
	}
	if(tab == "admin_project_actions" && window.is_admin){
		sel_tab.innerHTML = admin_project_actions.textContent;
	}
	if(tab == "admin_user" && window.is_admin){
		sel_tab.innerHTML = admin_user.textContent;
	}
	if(tab == "admin_user_actions" && window.is_admin){
		sel_tab.innerHTML = admin_user_actions.textContent;
	}
	prepare_view();
}
	
var xhr2 = new XMLHttpRequest();

/*
	Internal Functions
*/

function load_admin_stats(){
	if(window.is_admin){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=getStats', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					projects.textContent = result.projects;
					users.textContent = result.users;
					sessions.textContent = result.sessions;
					requests.textContent = result.requests;
				}	
			}
		}
	}
}

function admin_project_info(project_id){
	if(window.is_admin){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=getProjectInfo&project_id=' + project_id, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					choose_tab("admin_project_actions");
					project_name.textContent = result.project_name;
					if(result.verified == 1){
						verify_project.classList.add('button-secondary');
						verify_project.classList.remove('button-primary');
						verify_project.textContent = "Отозвать";
						
						let verification_mark = "&nbsp;<span class=\"verify_mark\">Verified</span>";
						project_name.innerHTML += verification_mark;
					}
					else{
						verify_project.classList.add('button-primary');
						verify_project.classList.remove('button-secondary');
						verify_project.textContent = "Подтвердить";
					}
					redirect_uri.textContent = result.redirect_uri;
					owner_id.textContent = "ID Владельца: " + result.owner_id;
					window.admin_current_project = project_id;
					window.admin_project_state = result.enabled;
					if(window.admin_project_state != 0){
						delete_project.classList.add('button-secondary');
						delete_project.classList.remove('button-primary');
						
						restore_project.classList.add('button-secondary');
						restore_project.classList.remove('button-primary');
					}
				}
				else{
					choose_tab("admin_project");
					alertify.notify("Такого проекта не существует, либо он был удалён.", 'error', 5);
				}
			}
		}
	}
}

function admin_user_info(user_email){
	if(window.is_admin){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=getUserInfo&email=' + user_email, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					choose_tab("admin_user_actions");
					user_name.textContent = result.user_name + " " + result.user_surname + " (" + result.user_nick + ")";
					admin_email.textContent = result.user_email;
					admin_id.textContent = "ID: " + result.user_id;
					
					let verification_mark = "";
					
					ban_user.classList.remove('button-secondary');
					ban_user.classList.add('button-primary');
					ban_user.textContent = "Заблокировать";
					current_ban_reason.classList.add('hidden-el');
					
					if(result.is_banned == 1){
						ban_user.classList.add('button-secondary');
						ban_user.classList.remove('button-primary');
						ban_user.textContent = "Разблокировать";
						
						current_ban_reason.classList.remove('hidden-el');
						current_ban_reason.textContent = "Причина Блокировки: " + result.ban_reason;
						current_ban_reason.innerHTML = "<br>" + current_ban_reason.innerHTML;
					}
					
					verify_user.classList.remove('button-secondary');
					verify_user.classList.add('button-primary');
					verify_user.textContent = "Подтвердить";
					
					if(result.verified == 1){
						verify_user.classList.add('button-secondary');
						verify_user.classList.remove('button-primary');
						verify_user.textContent = "Отозвать";
						
						verification_mark = "&nbsp;<span class=\"verify_mark\">Verified</span>";
					}
					
					if(result.admin){
						verify_user.classList.add('button-secondary');
						verify_user.classList.remove('button-primary');
						verify_user.textContent = "Администратор";
						
						verification_mark = "&nbsp;<span class=\"verify_mark\">Administrator</span>";
					}
					
					if(result['2fa_active'] != 1){
						sec_totp.classList.add('button-secondary');
						sec_totp.classList.remove('button-primary');
						sec_totp.textContent = "2FA (Disabled)";
					}
					else{
						sec_totp.classList.remove('button-secondary');
						sec_totp.classList.add('button-primary');
						sec_totp.textContent = "2FA (Enabled)";
					}
					
					if(result['easylogin'] != 1){
						sec_easylogin.classList.add('button-secondary');
						sec_easylogin.classList.remove('button-primary');
						sec_easylogin.textContent = "EasyLogin (Disabled)";
					}
					else{
						sec_easylogin.classList.remove('button-secondary');
						sec_easylogin.classList.add('button-primary');
						sec_easylogin.textContent = "EasyLogin (Enabled)";
					}
					
					if(result['email_check'] != 1){
						sec_emailcheck.classList.add('button-secondary');
						sec_emailcheck.classList.remove('button-primary');
						sec_emailcheck.textContent = "EMail Check (Disabled)";
					}
					else{
						sec_emailcheck.classList.remove('button-secondary');
						sec_emailcheck.classList.add('button-primary');
						sec_emailcheck.textContent = "EMail Check (Enabled)";
					}
					
					window.admin_user_result = result;
					user_name.innerHTML += verification_mark;
				}
				else{
					choose_tab("admin_user");
					alertify.notify("Пользователя с указанной почтой / ID не существует!", 'error', 5);
				}
			}
		}
	}
}

function admin_verify_user(){
	if(window.is_admin){
		if(window.admin_user_result.admin){
			alertify.notify("Подтверждение Администратора не может быть отозвано!", 'warning', 5);
			return;
		}
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=toggleUserVerify&user_id=' + window.admin_user_result.user_id, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					admin_user_info(window.admin_user_result.user_email);
				}
			}
		}
	}
}

function admin_reset_user_password(){
	if(window.is_admin){
		if(window.admin_user_result.admin){
			alertify.notify("Данное действие не может быть выполнено с аккаунтом администратора.", 'warning', 5);
			return;
		}
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=resetUserPassword&user_id=' + window.admin_user_result.user_id, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					alertify.notify("Действие было успешно выполнено.", 'success', 5);
					admin_user_info(window.admin_user_result.user_email);
				}
			}
		}
	}
}

function admin_reset_user_ip(){
	if(window.is_admin){
		if(window.admin_user_result.admin){
			alertify.notify("Данное действие не может быть выполнено с аккаунтом администратора.", 'warning', 5);
			return;
		}
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=resetUserIP&user_id=' + window.admin_user_result.user_id, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					alertify.notify("Действие было успешно выполнено.", 'success', 5);
					admin_user_info(window.admin_user_result.user_email);
				}
			}
		}
	}
}

function admin_reset_user_slid(){
	if(window.is_admin){
		if(window.admin_user_result.admin){
			alertify.notify("Данное действие не может быть выполнено с аккаунтом администратора.", 'warning', 5);
			return;
		}
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=resetUserSLID&user_id=' + window.admin_user_result.user_id, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					alertify.notify("Действие было успешно выполнено.", 'success', 5);
					admin_user_info(window.admin_user_result.user_email);
				}
			}
		}
	}
}

function admin_ban_user(){
	if(window.is_admin){
		if(window.admin_user_result.admin && window.admin_user_result.is_banned == 0){
			alertify.notify("Данное действие не может быть выполнено с аккаунтом администратора.", 'warning', 5);
			return;
		}
		if(window.admin_user_result.is_banned == 0){
			alertify.prompt('Причина', 'Укажите причину блокировки:', '',
				function(evt, value){
					var xhr = new XMLHttpRequest();
					xhr.open('GET', 'api.php?section=admin&method=banUser&user_id=' + window.admin_user_result.user_id + "&reason=" + encodeURIComponent(value), true);
					xhr.setRequestHeader("Authorization", "Bearer " + window.token);
					xhr.send();
					xhr.onload = function (e) {
						if (xhr.readyState == 4 && xhr.status == 200) {
							let result = JSON.parse(xhr.responseText);
							if(result.result == "OK"){
								alertify.notify("Действие было успешно выполнено.", 'success', 5);
								admin_user_info(window.admin_user_result.user_email);
							}
						}
					}
				},
				function(){
					return;
				}
			);
		}
		else{
			var xhr = new XMLHttpRequest();
			xhr.open('GET', 'api.php?section=admin&method=unbanUser&user_id=' + window.admin_user_result.user_id, true);
			xhr.setRequestHeader("Authorization", "Bearer " + window.token);
			xhr.send();
			xhr.onload = function (e) {
				if (xhr.readyState == 4 && xhr.status == 200) {
					let result = JSON.parse(xhr.responseText);
					if(result.result == "OK"){
						alertify.notify("Действие было успешно выполнено.", 'success', 5);
						admin_user_info(window.admin_user_result.user_email);
					}
				}
			}
		}
	}
}


function admin_delete_project(){
	if(window.is_admin && window.admin_project_state == 0){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=deleteProject&project_id=' + window.admin_current_project, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					choose_tab("admin_project");
				}
				else{
					alertify.notify("Этот проект не может быть удалён!", 'error', 5);
				}
			}
		}
	}
}

function admin_restore_project(){
	if(window.is_admin && window.admin_project_state == 0){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=restoreProject&project_id=' + window.admin_current_project, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					choose_tab("admin_project");
				}
				else{
					alertify.notify("Этот проект не может быть восстановлен!", 'error', 5);
				}
			}
		}
	}
}

function admin_verify_project(){
	if(window.is_admin){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=toggleProjectVerify&project_id=' + window.admin_current_project, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					admin_project_info(window.admin_current_project);
				}
			}
		}
	}
}

function admin_reset_project(){
	if(window.is_admin){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=resetProject&project_id=' + window.admin_current_project, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					admin_project_info(window.admin_current_project);
				}
			}
		}
	}
}

function purgeRequests(){
	if(window.is_admin){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=purgeRequests', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					load_admin_stats();
				}	
			}
		}
	}
}

function purgeSessions(){
	if(window.is_admin){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=admin&method=purgeSessions', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					load_admin_stats();
				}	
			}
		}
	}
}

function initQRReader(){
	window.html5QrCode = new Html5Qrcode("reader");
	const qrCodeSuccessCallback = (decodedText, decodedResult) => {
		console.log(`Code matched = ${decodedText}`, decodedResult);
		let container = document.getElementById("reader");
		let begin_with_url = "<?php echo(htmlspecialchars($login_site)) ?>";
		var given_loc = getLocation(decodedText);
		var true_loc = getLocation(begin_with_url);

		window.html5QrCode.stop();

		if(given_loc.hostname == true_loc.hostname){
			window.open(decodedText, "Подтверждение Входа");
			window.setTimeout(choose_tab, 2000, 'main');
		}
		else{
			alertify.notify("Сканер не предназначен для сканирования ссылок сторонних сервисов!", 'error', 2, function(){choose_tab('main')});
		}
	};

	window.html5QrCode.start({ facingMode: { exact: "environment"} }, { fps: 10, qrbox: { width: 250, height: 250 } }, qrCodeSuccessCallback).catch(err =>
		{
			alertify.confirm("Ошибка", "Произошла ошибка при работе с камерой!",
				function(){choose_tab('main')}, function(){choose_tab('main')}
			);
		}
	);
}

function regenerateAPI(){
	alertify.confirm("Переиздание API Ключей", "Этим действием вы ппереиздадите ваши API ключи! Это обнулит все предыдущие API ключи!",
		function(){
			var xhr = new XMLHttpRequest();
			xhr.open('GET', 'api.php?section=users&method=regenerateAPIKey', true);
			xhr.setRequestHeader("Authorization", "Bearer " + window.token);
			xhr.send();
			xhr.onload = function (e) {
				let result = JSON.parse(xhr.responseText);
				if(result.reason == 'RATE_LIMIT_EXCEEDED'){
					window.failed_request = function(){
						regenerateAPI();
					};
					callCaptcha();
					return;
				}
				location.reload();
			}
		},
		function(){}
	);
}

function show_api(){
	if(user_api.textContent != ""){
		user_api.textContent = "";
		show_api_btn.classList.remove('button-secondary');
		show_api_btn.classList.add('button-primary');

		show_api_btn.textContent = "Показать Ключ";
	}
	else{
		user_api.textContent = window.token;
		show_api_btn.classList.remove('button-primary');
		show_api_btn.classList.add('button-secondary');

		show_api_btn.textContent = "Скрыть Ключ";
	}
}

function regenerateSLID(){
	alertify.confirm("Подтверждение действия", "Вы принудительно закроете все сеансы!",
		function(){
			var xhr = new XMLHttpRequest();
			xhr.open('GET', 'api.php?section=users&method=regenerateSLID', true);
			xhr.setRequestHeader("Authorization", "Bearer " + window.token);
			xhr.send();
			xhr.onload = function (e) {
				let result = JSON.parse(xhr.responseText);
				if(result.reason == 'RATE_LIMIT_EXCEEDED'){
					window.failed_request = function(){
						regenerateSLID();
					};
					callCaptcha();
					return;
				}
				checkAPIToken();
			}
		},
		function(){ }
	);
}

function manage_totp(){
	if(window.security_info.totp == 0){
		choose_tab('totp_enable_form');
	}
	else{
		choose_tab('totp_disable_form');
	}
}

function prepare_totp_enable(){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=totp&method=prepareEnable', true);
	xhr.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr.send();
	xhr.onload = function (e) {
		if (xhr.readyState == 4 && xhr.status == 200) {
			let result = JSON.parse(xhr.responseText);
			let qr_link = result.url;
			let secret = result.secret;
			
			TOTP_QR.src = qr_link;
			otp_secret.innerHTML = secret;
		}
	}
}

function proceed_totp_enable(otp){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=totp&method=enable&otp=' + otp, true);
	xhr.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr.send();
	xhr.onload = function (e) {
		if (xhr.readyState == 4 && xhr.status == 200) {
			let result = JSON.parse(xhr.responseText);
			if(result.result == "OK"){
				choose_tab('totp_completed_form');
				disable_code.textContent = result.disableCode;
				window.security_info = undefined;
			}
			else{
				if(result.reason == "WRONG_TOTP"){
					alertify.notify("Введённый OTP код недействителен!", 'error', 5);
				}
				if(result.reason == 'RATE_LIMIT_EXCEEDED'){
					window.failed_request = function(){
						proceed_totp_enable(otp);
					};
					callCaptcha();
				}
			}
		}
	}
}

function proceed_totp_disable(otp){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=totp&method=disable&otp=' + otp, true);
	xhr.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr.send();
	xhr.onload = function (e) {
		if (xhr.readyState == 4 && xhr.status == 200) {
			let result = JSON.parse(xhr.responseText);
			if(result.result == "OK"){
				alertify.notify("Вы успешно отключили 2FA!", 'success', 2);
				window.security_info = undefined;
				choose_tab('security');
			}
			else{
				if(result.reason == "WRONG_TOTP"){
					alertify.notify("Введённый OTP код недействителен!", 'error', 5);
				}
				if(result.reason == 'RATE_LIMIT_EXCEEDED'){
					window.failed_request = function(){
						proceed_totp_disable(otp);
					};
					callCaptcha();
				}
			}
		}
	}
}

function getSecurityInfo(){	
	if(window.security_info == undefined){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=security&method=getSecurityInfo', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				window.security_info = result;
				if(result.email_check == 1){
					email_check.classList.remove('button-primary');
					email_check.classList.add('button-secondary');
					email_check.textContent = "Отключить";
				}
				if(result.email_check == 0){
					email_check.classList.remove('button-secondary');
					email_check.classList.add('button-primary');
					email_check.textContent = "Включить";
				}
				
				if(result.totp == 1){
					totp_state.classList.remove('button-primary');
					totp_state.classList.add('button-secondary');
					totp_state.textContent = "Отключить";
				}
				
				if(result.easylogin == 1){
					easylogin_state.classList.remove('button-primary');
					easylogin_state.classList.add('button-secondary');
					easylogin_state.textContent = "Отключить";
				}
				else{
					easylogin_state.classList.remove('button-secondary');
					easylogin_state.classList.add('button-primary');
					easylogin_state.textContent = "Включить";
				}
			}
		}
	}
	else{		
		if(window.security_info.email_check == 1){
			email_check.classList.remove('button-primary');
			email_check.classList.add('button-secondary');
			email_check.textContent = "Отключить";
		}
		if(window.security_info.email_check == 0){
			email_check.classList.remove('button-secondary');
			email_check.classList.add('button-primary');
			email_check.textContent = "Включить";
		}
		if(window.security_info.totp == 1){
			totp_state.classList.remove('button-primary');
			totp_state.classList.add('button-secondary');
			totp_state.textContent = "Отключить";
		}
		if(window.security_info.easylogin == 1){
			easylogin_state.classList.remove('button-primary');
			easylogin_state.classList.add('button-secondary');
			easylogin_state.textContent = "Отключить";
		}
		else{
			easylogin_state.classList.remove('button-secondary');
			easylogin_state.classList.add('button-primary');
			easylogin_state.textContent = "Включить";
		}	
	}
}

function manage_email(){
	if(window.security_info.email_check == 1){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=users&method=disableEMailCheck', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.reason == 'RATE_LIMIT_EXCEEDED'){
					window.failed_request = function(){
						manage_email();
					};
					callCaptcha();
					return;
				}
				window.security_info = undefined;
				getSecurityInfo();
			}
		}
	}
	else{
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=users&method=enableEMailCheck', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.reason == 'RATE_LIMIT_EXCEEDED'){
					window.failed_request = function(){
						manage_email();
					};
					callCaptcha();
					return;
				}
				window.security_info = undefined;
				getSecurityInfo();
			}
		}
	}
}

function manage_easylogin(){
	if(window.security_info.easylogin == 1){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=easylogin&method=disable', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				if (xhr.readyState == 4 && xhr.status == 200) {
					let result = JSON.parse(xhr.responseText);
					if(result.reason == 'RATE_LIMIT_EXCEEDED'){
						window.failed_request = function(){
							manage_easylogin();
						};
						callCaptcha();
						return;
					}
					window.security_info = undefined;
					getSecurityInfo();
				}
			}
		}
	}
	else{
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=easylogin&method=enable', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				if (xhr.readyState == 4 && xhr.status == 200) {
					let result = JSON.parse(xhr.responseText);
					if(result.reason == 'RATE_LIMIT_EXCEEDED'){
						window.failed_request = function(){
							manage_easylogin();
						};
						callCaptcha();
						return;
					}
					window.security_info = undefined;
					getSecurityInfo();
				}
			}
		}
	}
}

function prepare_main(){
	if(window.user_info == undefined){
		var xhr2 = new XMLHttpRequest();
		xhr2.open('GET', 'api.php?section=users&method=getUserInfo', true);
		xhr2.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr2.send();
		xhr2.onload = function (e) {
			let result = JSON.parse(xhr2.responseText);
			
			if(result.result == "OK"){
				window.user_info = result;
				let verification_mark = "&nbsp;<span class=\"verify_mark\">Verified</span>";
				if(result.verified != 1){
					verification_mark = "";
				}
				if(result.admin){
					verification_mark = "&nbsp;<span class=\"verify_mark\">Administrator</span>";
				}
				document.getElementById('user_name').innerHTML = result.user_name + " " + result.user_surname + verification_mark;
				
				document.getElementById('email').innerHTML = result.email;
				document.getElementById('email_changer').innerHTML = result.email;
				window.email = result.email;
				
				if(!window.admin_initalized){
					load_admin();
				}
			}
		}
	}
	else{
		let result = window.user_info;
		if(result.result == "OK"){
			let verification_mark = "&nbsp;<span class=\"verify_mark\">Verified</span>";
			if(result.verified != 1){
				verification_mark = "";
			}
			if(result.admin){
				verification_mark = "&nbsp;<span class=\"verify_mark\">Administrator</span>";
			}
			document.getElementById('user_name').innerHTML = result.user_name + " " + result.user_surname + verification_mark;
			
			document.getElementById('email').innerHTML = result.email;
			document.getElementById('email_changer').innerHTML = result.email;
			window.email = result.email;
			
			if(!window.admin_initalized){
				load_admin();
			}
		}
	}
}

function loadUserInfo(){
	if(window.user_info == undefined){
		var xhr2 = new XMLHttpRequest();
		xhr2.open('GET', 'api.php?section=users&method=getUserInfo', true);
		xhr2.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr2.send();
		xhr2.onload = function (e) {
			let result = JSON.parse(xhr2.responseText);
			if(result.result == "OK"){
				window.user_info = result;
				user_tag.value = result.user_nick;
				user_tag.previousElementSibling.classList.add('placeholder-upper');
				user_name.value = result.user_name;
				user_name.previousElementSibling.classList.add('placeholder-upper');
				user_surname.value = result.user_surname;
				user_surname.previousElementSibling.classList.add('placeholder-upper');
				user_birthday.valueAsNumber = result.user_bday * 1000;
				
				if(!window.admin_initalized){
					load_admin();
				}
			}
		}
	}
	else{
		let result = window.user_info;
		if(result.result == "OK"){
			user_tag.value = result.user_nick;
			user_tag.previousElementSibling.classList.add('placeholder-upper');
			user_name.value = result.user_name;
			user_name.previousElementSibling.classList.add('placeholder-upper');
			user_surname.value = result.user_surname;
			user_surname.previousElementSibling.classList.add('placeholder-upper');
			user_birthday.valueAsNumber = result.user_bday * 1000;
			
			if(!window.admin_initalized){
				load_admin();
			}
		}
	}
}

function load_admin(){
	if(window.user_info == undefined){
		var xhr2 = new XMLHttpRequest();
		xhr2.open('GET', 'api.php?section=users&method=getUserInfo', true);
		xhr2.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr2.send();
		xhr2.onload = function (e) {
			let result = JSON.parse(xhr2.responseText);
			if(result.result == "OK"){
				window.user_info = result;
				window.admin_initalized = true;
				if(result.admin){
					admin_item.classList.remove('hidden-el');
					window.is_admin = true;
				}
			}
		}
	}
	else{
		let result = window.user_info;
		if(result.result == "OK"){
			window.admin_initalized = true;
			if(result.admin){
				admin_item.classList.remove('hidden-el');
				window.is_admin = true;
			}
		}
	}
}

function genNewPwd(){
	let password = generatePass();
	new_password.value = password;
	new_password.previousElementSibling.classList.add('placeholder-upper');
}
	
function generatePass(){
	let arr = window.crypto.getRandomValues(new BigUint64Array(1))[0].toString(36).split("");
	arr = arr.concat(window.crypto.getRandomValues(new BigUint64Array(1))[0].toString(36).split(""));
	arr = arr.slice(0, 16);
	arr.forEach(function(element, index){
		if(Math.round(Math.random())){
			arr[index] = element.toUpperCase();
		}
	});
		
	return arr.join("");
}

function send_change_email(new_email){
	xhr2.open('GET', 'api.php?section=users&method=changeUserEmail&email=' + new_email, true);
	xhr2.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr2.send();
	xhr2.onload = function (e) {
		if (xhr2.readyState == 4 && xhr2.status == 200) {
			if(xhr2.responseText != ''){
				let result = JSON.parse(xhr2.responseText);
				if(result.reason == 'GIVEN_EMAIL_IS_INVALID'){
					alertify.notify("Вы ввели недействительный E-Mail!", 'error', 5);
				}
				if(result.reason == 'YOU_ARE_CURRENTLY_USING_THIS_EMAIL'){
					alertify.notify("Введённый E-Mail является вашей текущей почтой!", 'error', 5);
				}
				if(result.reason == 'DISPOSABLE_EMAIL'){
					alertify.notify("Данная почта не может быть использована!", 'error', 5);
				}
				if(result.reason == 'INVALID_EMAIL'){
					alertify.notify("Данная почта не может быть использована!", 'error', 5);
				}
				if(result.reason == 'RATE_LIMIT_EXCEEDED'){
					window.failed_request = function(){
						send_change_email(new_email);
					};
					callCaptcha();
				}
				if(result.result == "OK"){
					alertify.notify("Вам было отправлено письмо для подтверждения нового адреса E-Mail.", 'message', 5);
					choose_tab('main');
				}
			}
		}
	}
}

function change_password(old_password, new_password){
	document.cookie = "new_password_current=" + encodeURIComponent(old_password) + "; max-age=120";
	document.cookie = "new_password_new=" + encodeURIComponent(new_password) + "; max-age=120";
	
	xhr2.open('GET', 'api.php?section=users&method=changeUserPassword', true);
	xhr2.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr2.send();
	xhr2.onload = function (e) {
		let result = JSON.parse(xhr2.responseText);
		if(result.result == "OK"){
			alertify.notify("Вы успешно сменили ваш пароль!", 'success', 5);
			choose_tab('main');
		}
		else{
			if(result.reason == "WRONG_PASSWORD"){
				alertify.notify("Вы ввели неверный пароль!", 'error', 5);
			}
			if(result.reason == 'RATE_LIMIT_EXCEEDED'){
				window.failed_request = function(){
					change_password(old_password, new_password);
				};
				callCaptcha();
			}
		}
	}
}

function update_user_info(tag, name, surname, bday){
	bday = bday / 1000;
	if(tag.length < 3 || tag.length > 16){
		alertify.notify('Tag Пользователя не должен быть короче 3 символов!', 'error', 5);
		return;
	}
	if(name.length < 2 && name.length > 32){
		alertify.notify('Имя не должно быть короче 2 символов!', 'error', 5);
		return;
	}
	if(surname.length < 2 && surname.length > 32){
		alertify.notify('Фамилия не должна быть короче 2 символов!', 'error', 5);
		return;
	}
	if(bday == 0){
		alertify.notify('Укажите свою дату рождения!', 'error', 5);
	}
	
	xhr2.open('GET', '/api.php?section=register&method=saveInfo&user_name=' + encodeURIComponent(name) + '&user_surname=' + encodeURIComponent(surname) + '&user_nick=' + encodeURIComponent(tag) + '&birthday=' + encodeURIComponent(bday), true);
	xhr2.setRequestHeader("Authorization", "Bearer " + window.token);
	xhr2.send();
	xhr2.onload = function (e) {
		let ret = JSON.parse(xhr2.responseText);
		if(ret.result == "FAULT"){
			if(result.reason == 'RATE_LIMIT_EXCEEDED'){
				window.failed_request = function(){
					update_user_info(tag, name, surname, bday);
				};
				callCaptcha();
			}
			if(ret.reason == "MALFORMED_NICK"){
				alertify.notify('Tag Пользователя занят, либо содержит запрещённые знаки!', 'error', 5);
			}
			if(ret.reason == "MALFORMED_NAME"){
				alertify.notify('Имя содержит запрещённые знаки!', 'error', 5);
			}
			if(ret.reason == "MALFORMED_SURNAME"){
				alertify.notify('Фамилия содержит запрещённые знаки!', 'error', 5);
			}
			if(ret.reason == "MALFORMED_BIRTHDAY"){
				alertify.notify('Дата Рождения не указана!', 'error', 5);
			}
		}
		else{
			alertify.notify('Данные пользователя были обновлены!', 'success', 5);
			window.user_info = undefined;
			checkAPIToken();
		}
	}
}

function integrations(){
	location.href = "apps/";
}

function logout(){
	alertify.confirm("Выход", "Вы уверены, что хотите выйти?",
		function(){
			document.cookie = 'user_id=; Max-Age=0;';
			document.cookie = 'email=; Max-Age=0;';
			document.cookie = 'user_ip=; Max-Age=0;';
			document.cookie = 'user_verkey=; Max-Age=0;';
			document.cookie = 'session=; Max-Age=0;';
			document.cookie = 'SLID=; Max-Age=0;';
			document.cookie = 'ip_verify=; Max-Age=0;';
			document.cookie = 'totp_timestamp=; Max-Age=0;';
			document.cookie = 'totp_verification=; Max-Age=0;';
			location.href = "index.php";
		},
		function(){ }
	);
}

</script>