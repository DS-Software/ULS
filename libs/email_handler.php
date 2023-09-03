<?php

require_once 'libs' . DIRECTORY_SEPARATOR . 'apmailer.php';
		
class email{
	public function __construct($email_settings){
		global $disable_email;
		if($disable_email){
			returnError("UNABLE_TO_INIT_EMAIL");
		}
		$config = [
			'defaultFrom' => $email_settings['messageFrom'],
			'onError'     => function($error, $message, $transport) {
				global $email_settings;
				if ($email_settings['email_debug']){
					returnError($error);
				} 
				returnError("EMAIL_DELIVERY_FAULT");
			},
			'afterSend'   => function($text, $message, $layer) { $nothing = 0; },
			'transports'  => [        
				['smtp', 'host' => $email_settings['smtp'], 'ssl' => true, 'port' => $email_settings['port'], 'login' => $email_settings['login'], 'password' => $email_settings['password']]
			],
		];
		Mailer()->init($config);
	}
								
	public function message_send($messageSubject, $messageFrom, $messageTo, $message_HTML){
		$message = Mailer()->newHtmlMessage();
		$message->setSubject($messageSubject);
		$message->setSenderEmail($messageFrom);
		$message->addRecipient($messageTo);
		$message->addContent($message_HTML);
							
		Mailer()->sendMessage($message);
	}
}

function send_email($email_settings, $msg_to, $email_html, $subject){
	$email = new email($email_settings);
	$messageFrom = $email_settings['messageFrom'];
	
	$email->message_send($subject, $messageFrom, $msg_to, $email_html);
}