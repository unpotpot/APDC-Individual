package pt.unl.fct.di.apdc.firstwebapp.utils;

public class RegisterDataV1 {
	
	private String id;
	private String password;
	
	public RegisterDataV1() {}
	
	public RegisterDataV1(String id , String password) {
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

	
}
