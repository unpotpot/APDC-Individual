package pt.unl.fct.di.apdc.firstwebapp.utils;

public class ChangePasswordData {
	
	private AuthenticationToken token;
	private String oldPassword;
	private String newPassword;
	private String confirmation;
	
	public ChangePasswordData() {}

	public boolean validateNewPassword() {
		//password must not be null, must have at least 10 characters, one uppercase letter, one lowercase letter and one number
		if(newPassword == null || newPassword.length() < 10 ||!validatePassword()) {return false;}
				
		//confirmation must be equal to password
		if(!confirmation.equals(newPassword)) {return false;}
		
		return true;
	}
	
	
	
	public AuthenticationToken getToken() {
		return token;
	}

	public void setToken(AuthenticationToken token) {
		this.token = token;
	}

	public String getOldPassword() {
		return oldPassword;
	}

	public void setOldPassword(String oldPassword) {
		this.oldPassword = oldPassword;
	}

	public String getNewPassword() {
		return newPassword;
	}

	public void setNewPassword(String newPassword) {
		this.newPassword = newPassword;
	}

	public String getConfirmation() {
		return confirmation;
	}

	public void setConfirmation(String confimation) {
		this.confirmation = confimation;
	}
	
	private boolean validatePassword() {
		boolean upper =false;
		boolean lower = false;
		boolean number = false;
		
		for(int i = 0; i < newPassword.length(); i++) {
			char a  = newPassword.charAt(i);
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
