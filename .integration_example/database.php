<?php

class database{
	/*
		A test Database Provider, use your own DB provider instead of this one
	*/
	
	public function getUserIDByULSID($uls_id){
		/*
		Description:
			Returns user's ID in yout project if the account
			was created before, or NULL if it wasn't.
		Parameters:
			- $uls_id (ID of user's ULS account)
		Returns:
			- $user_id (ID of user's account in your project)
			- null
		*/
		$user_id = $uls_id;
		
		return $user_id;
	}
	
	public function createNewUser($uls_id){
		/*
			Description:
				Creates a user account in your database.
			Parameters:
				- $uls_id (ID of user's ULS account)
			Returns:
				- $user_id (ID of user's account in your project)
		*/
		
		$user_id = $uls_id;
		
		return $user_id;
	}
}

?>