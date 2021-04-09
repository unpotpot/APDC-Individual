package pt.unl.fct.di.apdc.firstwebapp.utils;

//Data for a user profile

public class ProfileData {
	
	private String visibility;
	private String userId;
	private String email;
	private String landline;
	private String cellphone;
	private String address;
	private String complementary_address;
	private String local;
	private String postal_code;
	
	public ProfileData() {}

	public ProfileData(String visibility, String userId, String email, String landline, String cellphone, String address, String complementary_address, String local, String postal_code) {
		this.visibility = visibility;
		this.userId = userId;
		this.email = email;
		this.landline = landline;
		this.cellphone = cellphone;
		this.address = address;
		this.complementary_address = complementary_address;
		this.local = local;
		this.postal_code = postal_code;
	}
	
	
	public boolean validate() {
		//profile type must be public or private
		if(!visibility.equals(ProfileTypes.PUBLIC.toString()) && !visibility.equals(ProfileTypes.PRIVATE.toString())) {return false;}
		
		//userId must not be null or empty
		if(userId == null || userId.isEmpty()) {return false;}
		
		//email must not be null and be properly constructed
		if(email == null || !email.matches("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,4}")) {return false;}
		
		//if landline is not empty, it must be of length 9 and only contain numbers
		if( !landline.isEmpty() && (landline.length() != 9 || !landline.matches("[0-9]+") )) {return false;} 
		
		//if cellphone is not empty, it must be of length 9, only contain numbers, and start with 96, 93 or 91
		if( !cellphone.isEmpty() && (cellphone.length() != 9 || !cellphone.matches("[0-9]+") ||(!cellphone.startsWith("96") && !cellphone.startsWith("93") && !cellphone.startsWith("91")))) {return false;}
		
		//no validation for address , complementary_address or local
		
		//if postal_code is not empty it must be of length 8 and contain 4 integers followed by a dash and then 3 integers
		if( !postal_code.isEmpty() && (postal_code.length() != 8) || postal_code.charAt(4) != '-' || !postal_code.split("-")[0].matches("[0-9]+") || !postal_code.split("-")[1].matches("[0-9]+") ){return false;}
		
		return true;
	}
	
	public String getVisibility() {
		return visibility;
	}

	public void setVisibility(String visibility) {
		this.visibility = visibility;
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

	public String getLandline() {
		return landline;
	}

	public void setLandline(String landline) {
		this.landline = landline;
	}

	public String getCellphone() {
		return cellphone;
	}

	public void setCellphone(String cellphone) {
		this.cellphone = cellphone;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getComplementary_address() {
		return complementary_address;
	}

	public void setComplementary_address(String complementary_address) {
		this.complementary_address = complementary_address;
	}

	public String getLocal() {
		return local;
	}

	public void setLocal(String local) {
		this.local = local;
	}

	public String getPostal_code() {
		return postal_code;
	}

	public void setPostal_code(String postal_code) {
		this.postal_code = postal_code;
	}
	
	
	
}
