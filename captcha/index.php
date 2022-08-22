<?php
include('captcha.php');

session_start();

$captcha = new CAPTCHA();

$_SESSION['captcha_keystring'] = $captcha->getKeyString();
$_SESSION['captcha_time'] = time();
?>