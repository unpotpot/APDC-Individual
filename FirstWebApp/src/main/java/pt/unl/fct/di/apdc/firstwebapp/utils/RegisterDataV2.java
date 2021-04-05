package pt.unl.fct.di.apdc.firstwebapp.utils;

public class RegisterDataV2 {
	private String id;
	private String password;
	private String confirmation;
	private String email;
	private String name;
	
	public RegisterDataV2() {}
	
	public RegisterDataV2(String id , String password, String confirmation, String email, String name) {
		this.id = id;
		this.password = password;
		this.confirmation = confirmation;
		this.email = email;
		this.name = name;
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
	
	public String getConfirmation() {
		return confirmation;
	}

	public void setConfirmation(String confirmation) {
		this.confirmation = confirmation;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public boolean validate() {
		if(this.id == null || this.id.equals("")) {
			return false;
		}
		
		if(this.password == null || this.password.equals("")) {
			return false;
		}
		
		if(!this.confirmation.equals(this.password)) {
			return false;
		}
		
		if (this.email == null || this.email.equals("") ||!this.email.contains("@")) {
			return false;
		}
		
		if(this.name == null || this.name.equals("")) {
			return false;
		}
		return true;
	}
}
