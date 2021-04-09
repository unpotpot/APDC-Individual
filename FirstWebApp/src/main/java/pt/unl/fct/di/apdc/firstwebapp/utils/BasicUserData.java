package pt.unl.fct.di.apdc.firstwebapp.utils;

public class BasicUserData {
	private String userId;
	private String email;
	private String visibility;
	private String role;
	
	public BasicUserData() {}

	public BasicUserData(String userId, String email, String visibility, String role) {
		this.userId = userId;
		this.email = email;
		this.visibility = visibility;
		this.role = role;
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

	public String getVisibility() {
		return visibility;
	}

	public void setVisibility(String visibility) {
		this.visibility = visibility;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}
	
	
}
