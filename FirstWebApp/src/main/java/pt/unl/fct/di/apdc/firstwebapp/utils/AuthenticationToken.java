package pt.unl.fct.di.apdc.firstwebapp.utils;

//Authentication token used for identity verification

public class AuthenticationToken {
	private String id;
	private String userId;
	private String userRole;
	private long creationDate;
	private long expirationDate;
	private String checksum;
	
	public AuthenticationToken() {}
	
	public AuthenticationToken(String id,String userId,String userRole,long creationDate, long expirationDate, String checksum) {
		this.id = id;
		this.userId = userId;
		this.userRole = userRole;
		this.creationDate = creationDate;
		this.expirationDate = expirationDate;
		this.checksum = checksum;
	}
	
	public boolean validate(String checksum,long now) {
		return !(!this.checksum.equals(checksum) || creationDate > now || expirationDate < now);
	}
	
	public String getId() {
		return id;
	}
	
	public void setId(String id) {
		this.id = id;
	}
	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}
	
	public String getUserRole() {
		return userRole;
	}

	public void setUserRole(String userRole) {
		this.userRole = userRole;
	}
	
	public long getCreationDate() {
		return creationDate;
	}

	public void setCreationDate(long creationDate) {
		this.creationDate = creationDate;
	}

	public long getExpirationDate() {
		return expirationDate;
	}

	public void setExpirationDate(long expirationDate) {
		this.expirationDate = expirationDate;
	}

	public String getChecksum() {
		return checksum;
	}

	public void setChecksum(String checksum) {
		this.checksum = checksum;
	}
	
	
}
