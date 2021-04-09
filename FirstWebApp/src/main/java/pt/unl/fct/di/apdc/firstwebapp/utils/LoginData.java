package pt.unl.fct.di.apdc.firstwebapp.utils;

//Data required for logging in

public class LoginData {
	
	private String userId;
	private String password;
	
	public LoginData() {}
	
	public LoginData(String userId, String password) {
		this.userId = userId;
		this.password = password;
	}
	
	public boolean validate() {
		
		if(userId == null || userId.equals("")) {
			return false;
		}
		
		if(password == null || password.equals("")) {
			return false;
		}
		
		return true;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	
}
