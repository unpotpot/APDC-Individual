package pt.unl.fct.di.apdc.firstwebapp.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

//Data required for new user registration

public class RegistrationData {
	
	private String userId;
	private String email;
	private String password;
	private String confirmation;
	
	public RegistrationData() {}
	
	public RegistrationData(String userId, String email, String password, String confirmation) {
		
		this.userId = userId;
		this.email = email;
		this.password = password;
		this.confirmation = confirmation;
	}
	
	public boolean validate() {
		
		
		//userId must not be null or empty
		if(userId == null || userId.isEmpty()) {return false;}
		
		//password must not be null, must have at least 10 characters, one uppercase letter, one lowercase letter and one number
		if(password == null || password.length() < 10 ||!validatePassword()) {return false;}
		
		//confirmation must be equal to password
		if(!confirmation.equals(password)) {return false;}
		
		//email must not be null and must be properly built
		if(email == null || !email.matches("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,4}")) {return false;}
		
		return true;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getConfirmation() {
		return confirmation;
	}

	public void setConfirmation(String confirmation) {
		this.confirmation = confirmation;
	}
	
	private boolean validatePassword() {
		boolean upper =false;
		boolean lower = false;
		boolean number = false;
		
		for(int i = 0; i < password.length(); i++) {
			char a  = password.charAt(i);
			if(Character.isLowerCase(a)) {
				lower = true;
			}
			if(Character.isUpperCase(a)) {
				upper =true;
			}
			if(Character.isDigit(a)) {
				number = true;
			}
			if(upper && lower && number) {
				return true;
			}
			
		}
		
		return false;
	}
}
