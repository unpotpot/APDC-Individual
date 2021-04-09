package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.LinkedList;
import java.util.logging.Logger;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;


import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.PathElement;
import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.QueryResults;
import com.google.cloud.datastore.StringValue;
import com.google.cloud.datastore.StructuredQuery.CompositeFilter;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.cloud.datastore.Transaction;
import com.google.datastore.v1.TransactionOptions;
import com.google.datastore.v1.TransactionOptions.ReadOnly;
import com.google.gson.Gson;

import pt.unl.fct.di.apdc.firstwebapp.utils.AuthenticationToken;
import pt.unl.fct.di.apdc.firstwebapp.utils.BasicUserData;
import pt.unl.fct.di.apdc.firstwebapp.utils.ChangePasswordData;
import pt.unl.fct.di.apdc.firstwebapp.utils.ChangeProfileData;
import pt.unl.fct.di.apdc.firstwebapp.utils.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.utils.ProfileData;
import pt.unl.fct.di.apdc.firstwebapp.utils.ProfileTypes;
import pt.unl.fct.di.apdc.firstwebapp.utils.RegistrationData;
import pt.unl.fct.di.apdc.firstwebapp.utils.Roles;

//Account and session management


@Path("/account")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class AccountsResource {
	
	private static final String SALT = "supersecretsalt"; //used in checksum for authentication token
	private static final String TOKEN_ID_FORMAT = "%s_%s"; //used in checksum for authentication token
	private static final String USER_PROFILE_FORMAT = "%s_profile"; //used in checksum for authentication token
	private final long TOKEN_DURATION = 1000 * 60 * 60 *2; //token is valid for 2h
	
	private static Logger log = Logger.getLogger(AccountsResource.class.getName());
	private final Gson g = new Gson();
	
	private Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
	
	public AccountsResource() {}//Always keep empty for Jersey to work
	
	@POST
	@Path("/register")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response register(RegistrationData data) {
		
		log.info(String.format("Attempting to create user with ID:[%s]\n", data.getUserId()));
		
		if(!data.validate()) {
			log.warning(String.format("Data invalid to register user with ID:[%s]", data.getUserId()));
			return Response.status(Status.BAD_REQUEST).build(); //Data invalid
		}
		Key userKey = userKeyFactory.newKey(data.getUserId());
		Entity newUser = Entity.newBuilder(userKey)
				.set("password", StringValue.newBuilder(DigestUtils.sha512Hex(data.getPassword())).setExcludeFromIndexes(true).build())//encrypting password and setting it a non-indexed
				.set("email",data.getEmail())
				.set("visibility", ProfileTypes.PRIVATE.toString())
				.set("status", true)
				.set("role",Roles.USER.toString())
				.set("logins",0l)
				.set("created", System.currentTimeMillis())
				.build();
		
		Key profileKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",data.getUserId())).setKind("Profile").newKey(String.format(USER_PROFILE_FORMAT, data.getUserId()));
		Entity userProfile = Entity.newBuilder(profileKey)
				.set("cellphone", "")
				.set("landline", "")
				.set("address","")
				.set("complementary_address", "")
				.set("local","")
				.set("postal_code", "")
				.build();
		
		Transaction txn = datastore.newTransaction();
		try {
			
			if(txn.get(userKey) != null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] already exists\n",data.getUserId()));
				return Response.status(Status.FORBIDDEN).build();//User already exists
			}
			
			txn.add(newUser,userProfile);
			txn.commit();
			log.info(String.format("Created user with ID:[%s] and PASSWORD:[%s]\n", data.getUserId(),data.getPassword()));
			return Response.ok().build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on resgistering user with ID:[%s]\n %s",data.getUserId(), e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after resgistering user with ID:[%s]\n",data.getUserId()));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}
	
	@PUT
	@Path("/delete")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response delete(AuthenticationToken token) {
		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning("Authentication token provided not valid");
			return Response.status(Status.FORBIDDEN).build(); //Data invalid
		}
		
		Key userKey = userKeyFactory.newKey(token.getUserId());
		Key profileKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",token.getUserId())).setKind("Profile").newKey(String.format(USER_PROFILE_FORMAT, token.getUserId()));
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",token.getUserId())).setKind("Token").newKey(token.getId());
		Transaction txn = datastore.newTransaction();
		
		log.info(String.format("Attempting to delete user with ID:[%s]\n", token.getUserId()));
		try {
			Entity user = txn.get(userKey);
			if(user == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] does not exist\n",token.getUserId()));
				return Response.status(Status.FORBIDDEN).build();//User does not exist
			}
			Entity storedToken = txn.get(tokenKey);
			if(storedToken == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] is not logged in with a token with ID:[%s]\n",token.getUserId(),token.getId()));
				return Response.status(Status.FORBIDDEN).build();//Token is not found
			}

			if(!storedToken.getString("checksum").equals(token.getChecksum())) {
				txn.rollback();
				log.warning(String.format("Provided token with ID:[%s] has invalid checksum\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();//Token is not valid(wrong checksum)
			}
			
			//delete all authentication tokens for account
			long logins = user.getLong("logins");
			Key extraTokenKey;
			for(long i = 0 ;i < logins;i++) {
				extraTokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",token.getUserId())).setKind("Token").newKey(String.format(TOKEN_ID_FORMAT, token.getUserId(),(""+i)));
				txn.delete(extraTokenKey);
			}
			
			txn.delete(profileKey,userKey);
			txn.commit();
			log.info(String.format("Deleted user with ID:[%s]\n", token.getUserId()));
			return Response.ok().build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on deleting user with ID:[%s]\n %s",token.getUserId(), e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after deleting user with ID:[%s]\n",token.getUserId()));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}
	
	@POST
	@Path("/login")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response login(LoginData data) {
		
		log.info(String.format("Attempting to login user with ID:[%s]\n", data.getUserId()));
		
		if(!data.validate()) {
			log.warning(String.format("Data invalid to login user with ID:[%s]", data.getUserId()));
			return Response.status(Status.BAD_REQUEST).build(); //Data invalid
		}
		
		Key userKey = userKeyFactory.newKey(data.getUserId());
		Transaction txn = datastore.newTransaction();
		
		try {
			
			Entity user = txn.get(userKey);
			if(user == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] does not exist\n %s",data.getUserId()));
				return Response.status(Status.FORBIDDEN).build();//User already exists
			}
			
			if(!user.getString("password").equals(DigestUtils.sha512Hex(data.getPassword()))) {
				txn.rollback();
				log.warning(String.format("Wrong password for user with ID:[%s]", data.getUserId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			if(!user.getBoolean("status")) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] is DISABLED\n %s",data.getUserId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			//create a tokenId for user (example user0, user1, user2)
			long tokenNumber = user.getLong("logins");
			String tokenId = String.format(TOKEN_ID_FORMAT, data.getUserId(),tokenNumber);
			Key tokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User",data.getUserId())).setKind("Token").newKey(tokenId);
			long creationDate = System.currentTimeMillis();
			long expirationDate = creationDate + TOKEN_DURATION;
			
			String checksum = DigestUtils.sha512Hex(tokenId+data.getUserId()+user.getString("role")+creationDate+expirationDate+SALT);
			
			
			Entity userToken = Entity.newBuilder(tokenKey)
					.set("checksum",checksum)
					.build();
			
			Entity updatedUser = Entity.newBuilder(user).set("logins",tokenNumber+1l).build();//update number of logins of user;
			
			txn.add(userToken);	
			txn.put(updatedUser);
			txn.commit();
			log.info(String.format("Logged in with ID:[%s]\n", data.getUserId()));
			AuthenticationToken token = new AuthenticationToken(tokenId,data.getUserId(),user.getString("role"),creationDate,expirationDate,checksum);
			return Response.ok(g.toJson(token)).build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on logging in user with ID:[%s]\n %s",data.getUserId(), e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after logging in user with ID:[%s]\n",data.getUserId()));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}
	
	@PUT
	@Path("/logout")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response logout(AuthenticationToken token) {
		
		log.info(String.format("Attempting to logout user with ID:[%s]\n", token.getUserId()));
		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid to logout user with ID:[%s]", token.getUserId()));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", token.getUserId())).setKind("Token").newKey(token.getId());
		Key userKey = userKeyFactory.newKey(token.getUserId());
		Transaction txn = datastore.newTransaction();
		
		try {
			Entity storedToken = txn.get(tokenKey);
			if(storedToken == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] is not logged in with this token\n",token.getUserId()));
				return Response.status(Status.FORBIDDEN).build();//User not logged in
			}
			
			if(!token.getChecksum().equals(storedToken.getString("checksum"))) {
				txn.rollback();
				log.warning(String.format("Provided token with ID:[%s] has invalid checksum\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();//Token not valid(wrong checksum)
			}
			
			Entity user = txn.get(userKey);
			
			Entity updatedUser = Entity.newBuilder(user)
					.set("logins",user.getLong("logins")-1l)
					.build();

			txn.delete(tokenKey);
			txn.put(updatedUser);
			txn.commit();
			log.info(String.format("Logged out user with ID:[%s]\n", token.getUserId()));
			return Response.ok().build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on loggin out user with ID:[%s]\n %s",token.getUserId(), e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after logging out user with ID:[%s]\n",token.getUserId()));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}
	
	@POST
	@Path("/profile")
	public Response getProfile(AuthenticationToken token) {
		log.info(String.format("Attempting to get profile of user with ID:[%s]\n", token.getUserId()));
		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid to get profile of user with ID:[%s]", token.getUserId()));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		Key userKey = userKeyFactory.newKey(token.getUserId());
		Key profileKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",token.getUserId())).setKind("Profile").newKey(String.format(USER_PROFILE_FORMAT,token.getUserId()));
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",token.getUserId())).setKind("Token").newKey(token.getId());
		Transaction txn = datastore.newTransaction(TransactionOptions.newBuilder().setReadOnly(ReadOnly.newBuilder().build()).build());
		try {
			
			Entity storedToken = txn.get(tokenKey);
			if(storedToken == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] is not logged in with this token\n",token.getUserId()));
				return Response.status(Status.FORBIDDEN).build();//User not logged in
			}
			
			if(!token.getChecksum().equals(storedToken.getString("checksum"))) {
				txn.rollback();
				log.warning(String.format("Provided token with ID:[%s] has invalid checksum\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();//Token not valid(wrong checksum)
			}
			
			Entity user = txn.get(userKey);
			
			if(user == null) {
				log.warning(String.format("User with ID:[%s] does not exist", token.getUserId()));
				txn.rollback();
				return Response.status(Status.FORBIDDEN).build(); //Token Invalid
			}
			Entity storedProfile = txn.get(profileKey);
			
			ProfileData profile = new ProfileData(user.getString("visibility"),token.getUserId(),user.getString("email"),storedProfile.getString("landline"),storedProfile.getString("cellphone"),
					storedProfile.getString("address"),storedProfile.getString("complementary_address"),storedProfile.getString("local"),storedProfile.getString("postal_code"));
			
			txn.commit();
			log.info(String.format("Got profile of user with ID:[%s]\n", token.getUserId()));
			return Response.ok(g.toJson(profile)).build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on getting profile  of user with ID:[%s]\n %s",token.getUserId(), e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after getting profile if user with ID:[%s]\n",token.getUserId()));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
		
	}
	
	@PUT
	@Path("/profile")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeProfile(ChangeProfileData data) {
		log.info(String.format("Attempting to change profile of user with ID:[%s]\n", data.getToken().getUserId()));
		
		if(!data.getProfile().validate()) {
			log.warning(String.format("New profile for user with ID:[%s] is invalid", data.getToken().getUserId()));
			return Response.status(Status.BAD_REQUEST).build(); //Profile Invalid
		}
		
		if(!validateToken(data.getToken(),System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid to logout user with ID:[%s]", data.getToken().getUserId()));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", data.getToken().getUserId())).setKind("Token").newKey(data.getToken().getId());
		Key userKey = userKeyFactory.newKey(data.getToken().getUserId());
		Key profileKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", data.getToken().getUserId())).setKind("Profile").newKey(String.format(USER_PROFILE_FORMAT, data.getToken().getUserId()));
		Transaction txn = datastore.newTransaction();
		
		try {
			Entity storedToken = txn.get(tokenKey);
			if(storedToken == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] is not logged in with this token\n",data.getToken().getUserId()));
				return Response.status(Status.FORBIDDEN).build();//User not logged in
			}
			
			if(!data.getToken().getChecksum().equals(storedToken.getString("checksum"))) {
				txn.rollback();
				log.warning(String.format("Provided token with ID:[%s] has invalid checksum\n",data.getToken().getId()));
				return Response.status(Status.FORBIDDEN).build();//Token not valid(wrong checksum)
			}
			
			Entity user = txn.get(userKey);
			if(user == null) {
				txn.delete(tokenKey);
				txn.commit();
				log.warning(String.format("Provided token with ID:[%s] is invalid \n",data.getToken().getId()));
				return Response.status(Status.FORBIDDEN).build();//Token is from deleted account
			}
			
			Entity updatedUser = Entity.newBuilder(user)
					.set("email",data.getProfile().getEmail())
					.set("visibility", data.getProfile().getVisibility())
					.build();
				
			
			Entity profile = txn.get(profileKey);
			
			Entity updatedProfile = Entity.newBuilder(profile)
					.set("landline", data.getProfile().getLandline())
					.set("cellphone", data.getProfile().getCellphone())
					.set("address",data.getProfile().getAddress())
					.set("complementary_address", data.getProfile().getComplementary_address())
					.set("local",data.getProfile().getLocal())
					.set("postal_code", data.getProfile().getPostal_code())
					.build();
			
			txn.put(updatedUser,updatedProfile);
			txn.commit();
			log.info(String.format("Changed profile of user with ID:[%s]\n", data.getToken().getUserId()));
			return Response.ok().build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on loggin out user with ID:[%s]\n %s",data.getToken().getUserId(), e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after logging out user with ID:[%s]\n",data.getToken().getUserId()));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}
	
	@PUT
	@Path("/password")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changePassword(ChangePasswordData data) {
		log.info(String.format("Attempting to change password of user with ID:[%s]\n", data.getToken().getUserId()));
		
		if(!data.validateNewPassword()) {
			log.warning(String.format("New password of user with ID:[%s] is not valid", data.getToken().getUserId()));
			return Response.status(Status.BAD_REQUEST).build(); //Invalid new password
		}
		
		if(!validateToken(data.getToken(),System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid to change password of user with ID:[%s]", data.getToken().getUserId()));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		
		
		
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", data.getToken().getUserId())).setKind("Token").newKey(data.getToken().getId());
		Key userKey = userKeyFactory.newKey(data.getToken().getUserId());
		Transaction txn = datastore.newTransaction();
		
		try {
			Entity storedToken = txn.get(tokenKey);
			if(storedToken == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] is not logged in with this token\n",data.getToken().getUserId()));
				return Response.status(Status.FORBIDDEN).build();//User not logged in
			}
			
			if(!data.getToken().getChecksum().equals(storedToken.getString("checksum"))) {
				txn.rollback();
				log.warning(String.format("Provided token with ID:[%s] has invalid checksum\n",data.getToken().getId()));
				return Response.status(Status.FORBIDDEN).build();//Token not valid(wrong checksum)
			}
			
			Entity user = txn.get(userKey);
			if(user == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] does not exist", data.getToken().getUserId()));
				return Response.status(Status.FORBIDDEN).build();//Token is from deleted account
			}
			
			Entity updatedUser = Entity.newBuilder(user)
					.set("password", StringValue.newBuilder(DigestUtils.sha512Hex(data.getNewPassword())).setExcludeFromIndexes(true).build())
					.build();
				
			
			txn.put(updatedUser);
			txn.commit();
			log.info(String.format("Changed profile of user with ID:[%s]\n", data.getToken().getUserId()));
			return Response.ok().build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on loggin out user with ID:[%s]\n %s",data.getToken().getUserId(), e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after logging out user with ID:[%s]\n",data.getToken().getUserId()));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}
	
	
	@POST
	@Path("/listPublicLoggedInUsers")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response getListPublicUsersLoggedIn(AuthenticationToken token) {
		log.info("Attempting to get list of loged in users with public profiles");
		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid with ID:[%s]", token.getUserId()));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		
		Query<Entity> query = Query.newEntityQueryBuilder().setKind("User").setFilter(CompositeFilter.and( PropertyFilter.eq("role", Roles.USER.toString()), PropertyFilter.ge("logins", 1))).build();
		LinkedList<BasicUserData> data = new LinkedList<BasicUserData>();
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", token.getUserId())).setKind("Token").newKey(token.getId());
		Key userKey = userKeyFactory.newKey(token.getUserId());
		Transaction txn = datastore.newTransaction(TransactionOptions.newBuilder().setReadOnly(ReadOnly.newBuilder().build()).build());
		try {
			
			Entity storedToken = txn.get(tokenKey);
			if(storedToken == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] is not logged in with this token\n",token.getUserId()));
				return Response.status(Status.FORBIDDEN).build();//User not logged in
			}
			
			if(!token.getChecksum().equals(storedToken.getString("checksum"))) {
				txn.rollback();
				log.warning(String.format("Provided token with ID:[%s] has invalid checksum\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();//Token not valid(wrong checksum)
			}
			
			Entity tokenUser = txn.get(userKey);
			if(tokenUser == null) {
				txn.delete(tokenKey);
				txn.commit();
				log.warning(String.format("Provided token with ID:[%s] is invalid \n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();//Token is from deleted account
			}
			
			QueryResults<Entity> users = txn.run(query);
			while(users.hasNext()) {
				Entity user = users.next();
				data.add(new BasicUserData(user.getKey().getName(),user.getString("email"),user.getString("visibility"),user.getString("role")));
			}
			log.info("Got list of logged in users with public profile\n");
			txn.commit();
			return Response.ok(g.toJson(data)).build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe("DatastoreException on getting list of  logged in users public profiles \n");
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe("Transaction was active after getting list of  logged in users public profiles ");
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}
	
	private boolean validateToken(AuthenticationToken token, long now) {
		String checksum = DigestUtils.sha512Hex(token.getId()+token.getUserId()+token.getUserRole()+token.getCreationDate()+token.getExpirationDate()+SALT);
		return token.validate(checksum,now);
		
	}
	
}
