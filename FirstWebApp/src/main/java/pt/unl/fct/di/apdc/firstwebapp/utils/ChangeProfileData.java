package pt.unl.fct.di.apdc.firstwebapp.utils;

public class ChangeProfileData {
	
	private AuthenticationToken token;
	private ProfileData profile;
	
	public ChangeProfileData() {}
	
	public boolean validate(String checksum, long now) {
		return token.validate(checksum,now) && profile.validate();
	}
	
	public AuthenticationToken getToken() {
		return token;
	}
	
	public void setToken(AuthenticationToken token) {
		this.token = token;
	}

	public ProfileData getProfile() {
		return profile;
	}

	public void setProfile(ProfileData profile) {
		this.profile = profile;
	}
	
	
}
