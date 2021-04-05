package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
//import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.Consumes;
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
import com.google.cloud.datastore.Transaction;
import com.google.datastore.v1.TransactionOptions;
import com.google.datastore.v1.TransactionOptions.ReadOnly;
import com.google.gson.Gson;

import pt.unl.fct.di.apdc.firstwebapp.utils.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.utils.LoginDataV2;
import pt.unl.fct.di.apdc.firstwebapp.utils.AuthenticationToken;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {
	
	private static Logger log = Logger.getLogger(LoginResource.class.getName());
	private final Gson g = new Gson();
	
	private Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
	
	public LoginResource(){} //Always keep empty for Jersey to work
	
	//Task 3
	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response loginV1(LoginData data) {
		log.fine(String.format("Attempting to login user with ID:[%s]", data.getId()));
		
		Key userKey = userKeyFactory.newKey(data.getId());
		try {
			Entity user = datastore.get(userKey);
			if(user == null) {
				return Response.status(Status.FORBIDDEN).entity("User and/or password invalid.").build();//actually a user not found
			}
			if(!user.getString("password").equals(DigestUtils.sha512Hex(data.getPassword()))) {
				return Response.status(Status.FORBIDDEN).entity("User and/or password invalid.").build();
			}
			
		}
		catch(DatastoreException e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
		}
		log.fine(String.format("Successfuly logged in user with ID:[%s]", data.getId()));
		return Response.ok(g.toJson(new AuthenticationToken(data.getId()))).build();
	}
	
	//Task 4
	@POST
	@Path("/v2")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response loginV2(LoginDataV2 data) {
		log.info(String.format("Attempting to login user with ID:[%s]", data.getId()));
		
		if(!data.validate()) {
			log.warning(String.format("Data invalid to login user with ID:[%s]", data.getId()));
			return Response.status(Status.FORBIDDEN).build();//Data invalid
		}
		
		Key userKey = userKeyFactory.newKey(data.getId());
		Transaction txn = datastore.newTransaction();
		try {
			Entity user = txn.get(userKey);
			if(user == null) {
				log.warning(String.format("No user with ID:[%s]", data.getId()));
				txn.rollback();
				return Response.status(Status.FORBIDDEN).build();//User not found
			}
			if(!user.getString("password").equals(DigestUtils.sha512Hex(data.getPassword()))) {
				
				//increment failed logins
				
				txn.rollback();
				log.warning(String.format("Wrong password for user with ID:[%s]", data.getId()));
				return Response.status(Status.FORBIDDEN).build();
			}
			
			
			//create log with time, ip and location of connection 
			//increment successful logins
			
			txn.commit();
			log.info(String.format("Successfuly logged in user with ID:[%s]", data.getId()));
			return Response.ok(g.toJson(new AuthenticationToken(data.getId()))).build();
		}
		catch(DatastoreException e) {
			log.severe(String.format("DatastoreException on logging in user with ID:[%s]\n %s",data.getId(), e.toString()));
			txn.rollback();
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after logging in user with ID:[%s]\n",data.getId()));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();//Transaction was active
			}
		}
		
	}
	
	
	//Task 5
	@GET
	@Path("/user/")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response loginListV1(LoginDataV2 data) {
		log.fine(String.format("Attempting to fecth login list of last 24h of user with ID:[%s]", data.getId()));
		
		Key userKey = userKeyFactory.newKey(data.getId());
		Transaction txn = datastore.newTransaction(TransactionOptions.newBuilder().setReadOnly(ReadOnly.newBuilder().build()).build());//Create read-only transaction
		
		try {
			Entity user = txn.get(userKey);
			if(user == null) {
				return Response.status(Status.FORBIDDEN).build();//User not found
			}
			if(!user.getString("password").equals(DigestUtils.sha512Hex(data.getPassword()))) {
				return Response.status(Status.FORBIDDEN).build(); //Wrong password
			}
			
			log.fine(String.format("Successfuly fecthed login list of last 24h of user with ID:[%s]", data.getId()));
			txn.commit();
			return Response.ok().build();
		}
		catch(DatastoreException e) {
			log.severe(String.format("DatastoreException on fecthing login list of last 24h of user with ID:[%s]\n %s",data.getId(), e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after fecthing login list of last 24h of user with ID:[%s]\n",data.getId()));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();//Transaction was active
			}
		}
	}
	
	
	/**
	@POST
	@Path("/")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLogin(LoginData data) {
		
		log.fine(String.format("Login attempt by user [%s]",data.getId()));
		
		if(data.getId().equals("test") && data.getPassword().equals("password")) {
			
			return Response.ok(g.toJson( new AuthenticationToken(data.getId()))).build();
			
		}
		
		return Response.status(Status.FORBIDDEN).entity("User or password not valid.").build();
	}
	
	
	@GET
	@Path("/{id}")
	public Response checkUsername(@PathParam("id") String id) {
		
		log.fine(String.format("Checking if [%s] is a valid id",id.trim()));
		
		return Response.ok().entity(g.toJson(id.trim().equals("test"))).build();
		
	}
	**/
	
	
}
