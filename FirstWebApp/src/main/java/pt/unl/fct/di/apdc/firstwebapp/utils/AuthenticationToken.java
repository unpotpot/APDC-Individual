package pt.unl.fct.di.apdc.firstwebapp.utils;

import java.util.UUID;

public class AuthenticationToken {
	
	
	private static final long EXPIRATION_TIME = 1000*60*60*2;//2h
	
	private String id;
	private String tokenID;
	private long creationDate;
	private long expirationDate;
	
	public AuthenticationToken() {}
	
	public AuthenticationToken(String id) {
		this.id = id;
		this.tokenID = UUID.randomUUID().toString();
		this.creationDate = System.currentTimeMillis();
		this.expirationDate = this.creationDate + EXPIRATION_TIME;
	}
	
	public String getId() {
		return id;
	}
	public void setId(String username) {
		this.id = username;
	}
	public String getTokenID() {
		return tokenID;
	}
	public void setTokenID(String tokenID) {
		this.tokenID = tokenID;
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
	public static long getExpirationTime() {
		return EXPIRATION_TIME;
	}
}
