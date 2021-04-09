package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.LinkedList;
import java.util.logging.Logger;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
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
import com.google.cloud.datastore.Transaction;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.datastore.v1.TransactionOptions;
import com.google.datastore.v1.TransactionOptions.ReadOnly;
import com.google.gson.Gson;

import pt.unl.fct.di.apdc.firstwebapp.utils.AuthenticationToken;
import pt.unl.fct.di.apdc.firstwebapp.utils.BasicUserData;
import pt.unl.fct.di.apdc.firstwebapp.utils.ProfileData;
import pt.unl.fct.di.apdc.firstwebapp.utils.Roles;

//Operations that are can be restricted by ROLE

@Path("/ops")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class RestrictedOperationsResource {
	
	private static final String SALT = "supersecretsalt"; //used in checksum for authentication token
	private static final String TOKEN_ID_FORMAT = "%s_%s"; //used in checksum for authentication token
	private static final String USER_PROFILE_FORMAT = "%s_profile"; //used in checksum for authentication token
	
	private static Logger log = Logger.getLogger(AccountsResource.class.getName());
	private final Gson g = new Gson();
	
	private Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
	
	public RestrictedOperationsResource() {}
	
	@PUT
	@Path("/delete/{userId}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response deleteOther(AuthenticationToken token, @PathParam("userId") String userId) {
		
		log.info(String.format("Attempting to delete user with ID:[%s]\n",userId));
		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid to delete user with ID:[%s]", userId));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",token.getUserId())).setKind("Token").newKey(token.getId());
		
		Key deleteKey = userKeyFactory.newKey(userId);
		Key deleteProfile = datastore.newKeyFactory().addAncestor(PathElement.of("User",userId)).setKind("Profile").newKey(String.format(USER_PROFILE_FORMAT,userId));
		
		Transaction txn = datastore.newTransaction();
		try {
			Entity storedToken = txn.get(tokenKey);
			if(storedToken == null) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not exist\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			if(!storedToken.getString("checksum").equals(token.getChecksum())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] has invalid checksum\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			//Only GA  and SU can delete others accounts
			if(!token.getUserRole().equals(Roles.GA.toString())  && !token.getUserRole().equals(Roles.SU.toString())) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] cannot delete other USER accounts\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			Entity deleteUser = txn.get(deleteKey);
			if(deleteUser == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] does not exist\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			//no one can delete SU or GA
			if(deleteUser.getString("role").equals(Roles.SU.toString()) || deleteUser.getString("role").equals(Roles.GA.toString())) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] cannot be deleted by user with ID[%s]\n",userId,token.getUserId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			//delete tokens the user might have
			long logins = deleteUser.getLong("logins");
			Key extraTokenKey;
			for(long i = 0 ;i < logins;i++) {
				extraTokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",userId)).setKind("Token").newKey(String.format(TOKEN_ID_FORMAT, userId,(""+i)));
				txn.delete(extraTokenKey);
			}
			
			txn.delete(deleteProfile,deleteKey);
			txn.commit();
			log.info(String.format("Deleted user with ID:[%s] \n", userId));
			return Response.ok().build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on deleting user with ID:[%s]\n %s",userId, e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after deleting user with ID:[%s]\n",userId));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}

	@PUT
	@Path("/changeRole/{userId}/{role}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeRole(AuthenticationToken token, @PathParam("userId") String userId, @PathParam("role") String role) {
		log.info(String.format("Attempting to change role of user with ID:[%s]\n",userId));
		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid to change role of user with ID:[%s]", userId));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		if(!role.equals(Roles.USER.toString()) && !role.equals(Roles.GBO.toString()) && !role.equals(Roles.GA.toString()) ) {
			log.warning(String.format("Role [%s] is invalid",role));
			return Response.status(Status.FORBIDDEN).build(); //Role Invalid
		}
		
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",token.getUserId())).setKind("Token").newKey(token.getId());
		Key userKey = userKeyFactory.newKey(userId);
		Transaction txn = datastore.newTransaction();
		try {
			Entity storedToken = txn.get(tokenKey);
			if(storedToken == null) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not exist\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			if(!storedToken.getString("checksum").equals(token.getChecksum())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] has invalid checksum\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			//USER and GBO cant change roles
			if(token.getUserRole().equals(Roles.USER.toString()) || token.getUserRole().equals(Roles.GBO.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to change roles\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			//only SU can change to GA
			if(role.equals(Roles.GA.toString()) && !token.getUserRole().equals(Roles.SU.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to change role to GA\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			Entity user = txn.get(userKey);
			if(user == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] does not exist\n",userId));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			if(user.getString("role").equals(Roles.SU.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to change role to USER\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			if(user.getString("role").equals(Roles.GA.toString()) && !token.getUserRole().equals(Roles.SU.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to change role to USER\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			
			Entity changedUser =  Entity.newBuilder(user).set("role",role).build();
			
			txn.update(changedUser);
			txn.commit();
			log.info(String.format("Changed role of user with ID:[%s] \n", userId));
			return Response.ok().build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on deleting user with ID:[%s]\n %s",userId, e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after deleting user with ID:[%s]\n",userId));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}

	@PUT
	@Path("/changeStatus/{userId}/{status}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeStatus(AuthenticationToken token, @PathParam("userId") String userId, @PathParam("status") boolean status) {		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid to change role of user with ID:[%s]", userId));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",token.getUserId())).setKind("Token").newKey(token.getId());
		Key userKey = userKeyFactory.newKey(userId);
		Transaction txn = datastore.newTransaction();
		try {
			Entity storedToken = txn.get(tokenKey);
			if(storedToken == null) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not exist\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			if(!storedToken.getString("checksum").equals(token.getChecksum())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] has invalid checksum\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			//USER cant change status
			if(token.getUserRole().equals(Roles.USER.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to change status\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			Entity user = txn.get(userKey);
			if(user == null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] does not exist\n",userId));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			if(user.getString("role").equals(Roles.SU.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to change status of user [%s]\n",userId));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			if(user.getString("role").equals(Roles.GA.toString()) && !token.getUserRole().equals(Roles.SU.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to change status of user [%s]\n",userId));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			if(user.getString("role").equals(Roles.GBO.toString()) && !token.getUserRole().equals(Roles.SU.toString()) && !token.getUserRole().equals(Roles.GA.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to change status of user [%s]\n",userId));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			Entity changedUser =  Entity.newBuilder(user).set("status",status).build();
			
			txn.update(changedUser);
			txn.commit();
			log.info(String.format("Changed role of user with ID:[%s] \n", userId));
			return Response.ok().build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on deleting user with ID:[%s]\n %s",userId, e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after deleting user with ID:[%s]\n",userId));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}
	
	@POST
	@Path("/data/{userId}")
	@Consumes(MediaType.APPLICATION_JSON) 
	public Response getProfile(AuthenticationToken token , @PathParam("userId") String userId) {
		log.info(String.format("Attempting to get profile of user with ID:[%s]\n", token.getUserId()));
		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid to get profile of user with ID:[%s]", token.getUserId()));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		Key userKey = userKeyFactory.newKey(userId);
		Key profileKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",userId)).setKind("Profile").newKey(String.format(USER_PROFILE_FORMAT,userId));
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
			
			//USER cannot do this
			if(token.getUserRole().equals(Roles.USER.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to get arbitrary profiles\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			
			Entity user = txn.get(userKey);
			
			if(user == null) {
				log.warning(String.format("User with ID:[%s] does not exist", token.getUserId()));
				txn.rollback();
				return Response.status(Status.FORBIDDEN).build(); //Token Invalid
			}
			Entity storedProfile = txn.get(profileKey);
			
			ProfileData profile = new ProfileData(user.getString("visibility"),token.getUserId(),user.getString("email"),storedProfile.getString("landline"),storedProfile.getString("cellphone"),
					storedProfile.getString("address"),storedProfile.getString("complementary_address"),storedProfile.getString("local"),storedProfile.getString("zipcode"));
			
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
	
	@POST
	@Path("/listUsers")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response getListUsers(AuthenticationToken token) {
		log.info("Attempting to get list of loged in users with public profiles");
		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid with ID:[%s]", token.getUserId()));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		
		Query<Entity> query = Query.newEntityQueryBuilder().setKind("User").build();
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
			
			//USER cannot do this operation
			if(token.getUserRole().equals(Roles.USER.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to list all users\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
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
	
	@POST
	@Path("/listUsersLoggedIn")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response getListUsersLoggedIn(AuthenticationToken token) {
		log.info("Attempting to get list of loged in users with public profiles");
		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid with ID:[%s]", token.getUserId()));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		
		Query<Entity> query = Query.newEntityQueryBuilder().setKind("User").setFilter(PropertyFilter.ge("logins", 1)).build();
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
			
			//USER cannot do this operation
			if(token.getUserRole().equals(Roles.USER.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to list all users\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
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
	
	@POST
	@Path("/listUsersRole/{role}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response getListUsersRole(AuthenticationToken token, @PathParam("role") String role) {
		log.info("Attempting to get list of loged in users with public profiles");
		
		if(!validateToken(token,System.currentTimeMillis())) {
			log.warning(String.format("Authentication token invalid with ID:[%s]", token.getUserId()));
			return Response.status(Status.FORBIDDEN).build(); //Token Invalid
		}
		
		if(!role.equals(Roles.USER.toString()) && !role.equals(Roles.GBO.toString()) && !role.equals(Roles.GA.toString()) && !role.equals(Roles.SU.toString())) {
			log.warning(String.format("Provided role [%s] is invalid", role));
			return Response.status(Status.BAD_REQUEST).build(); //Role Invalid
		}
		
		Query<Entity> query = Query.newEntityQueryBuilder().setKind("User").setFilter(PropertyFilter.eq("role", role)).build();
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
			
			//USER cannot do this operation
			if(token.getUserRole().equals(Roles.USER.toString())) {
				txn.rollback();
				log.warning(String.format("Token with ID:[%s] does not have permission to list all users\n",token.getId()));
				return Response.status(Status.FORBIDDEN).build();
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
