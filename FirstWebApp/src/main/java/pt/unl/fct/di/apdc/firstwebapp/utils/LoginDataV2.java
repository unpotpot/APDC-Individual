package pt.unl.fct.di.apdc.firstwebapp.utils;

public class LoginDataV2 {
	
	private String id;
	private String password;
	
	public LoginDataV2() {}
	
	public LoginDataV2(String id, String password) {
		this.id = id;
		this.password = password;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	public boolean validate() {
		
		if(this.id == null || this.id.equals("")) {
			return false;
		}
		
		if(this.password == null || this.password.equals("")) {
			return false;
		}
		
		return true;
	}
}
