package pt.unl.fct.di.apdc.firstwebapp.resources;

//import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
//import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import java.util.logging.Logger;

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
import com.google.cloud.datastore.StringValue;
import com.google.cloud.datastore.Transaction;

import pt.unl.fct.di.apdc.firstwebapp.utils.RegisterDataV1;
import pt.unl.fct.di.apdc.firstwebapp.utils.RegisterDataV2;

@Path("/register")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class RegisterResource {
	
	private Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
	private static Logger log = Logger.getLogger(RegisterResource.class.getName());
	
	public RegisterResource() {}
	
	
	//Task 1
	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response registerV1(RegisterDataV1 data) {
		log.fine(String.format("Attempting to create user with ID:[%s] and password:[%s]", data.getId(),data.getPassword()));
		
		Key userKey = userKeyFactory.newKey(data.getId());
		
		Entity newUser = Entity.newBuilder(userKey)
				.set("password", DigestUtils.sha512Hex(data.getPassword()))
				.set("created", System.currentTimeMillis())
				.build();
		try {
			datastore.add(newUser);
			log.fine(String.format("Created user with ID:[%s] and password:[%s]", data.getId(),data.getPassword()));
			return Response.ok("User resgistered.").build();
		}
		catch(DatastoreException e) {
			if(e.getReason().equals("ALREADY_EXISTS")) {
				return Response.status(Status.CONFLICT).entity("User already exists.").build();
			}
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
		}
	}
	
	//Task 2
	@POST
	@Path("/v2")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response registerV2(RegisterDataV2 data) {
		log.fine(String.format("Attempting to create user with ID:[%s] and password:[%s]\n", data.getId(),data.getPassword()));
		
		if(!data.validate()) {
			return Response.status(Status.FORBIDDEN).entity("Information invalid.").build();
		}
		
		Key userKey = userKeyFactory.newKey(data.getId());
		
		Entity newUser = Entity.newBuilder(userKey)
				.set("password", DigestUtils.sha512Hex(data.getPassword()))
				.set("email",data.getEmail())
				.set("name", data.getName())
				.set("created", System.currentTimeMillis())
				.build();
		try {
			datastore.add(newUser);
			log.fine(String.format("Created user with ID:[%s] and password:[%s]\n", data.getId(),data.getPassword()));
			return Response.ok("User resgistered.").build();
		}
		catch(DatastoreException e) {
			if(e.getReason().equals("ALREADY_EXISTS")) {
				return Response.status(Status.CONFLICT).entity("User already exists.").build();
			}
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
		}
	}
	
	
	//Final
	@POST
	@Path("/v3")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response regsterV3(RegisterDataV2 data) {
		log.info(String.format("Attempting to create user with ID:[%s]\n", data.getId()));
		
		if(!data.validate()) {
			log.warning(String.format("Data invalid to login user with ID:[%s]", data.getId()));
			return Response.status(Status.BAD_REQUEST).build(); //Data invalid
		}
		
		Key userKey = userKeyFactory.newKey(data.getId());
		Transaction txn = datastore.newTransaction();
		try {
			
			if(txn.get(userKey) != null) {
				txn.rollback();
				log.warning(String.format("User with ID:[%s] already exists\n %s",data.getId()));
				return Response.status(Status.FORBIDDEN).build();//User already exists
			}
			
			Entity newUser = Entity.newBuilder(userKey)
					.set("password", StringValue.newBuilder(DigestUtils.sha512Hex(data.getPassword())).setExcludeFromIndexes(true).build())//encrypting password and setting it a non-indexed
					.set("email",data.getEmail())
					.set("name", data.getName())
					.set("created", System.currentTimeMillis())
					.build();

			txn.add(newUser);
			txn.commit();
			log.info(String.format("Created user with ID:[%s] and PASSWORD:[%s]\n", data.getId(),data.getPassword()));
			return Response.ok().build();
		}
		catch(DatastoreException e) {
			txn.rollback();
			log.severe(String.format("DatastoreException on resgistering user with ID:[%s]\n %s",data.getId(), e.toString()));
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();//Internal server error
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
				log.severe(String.format("Transaction was active after logging in user with ID:[%s]\n",data.getId()));
				return Response.status(Status.INTERNAL_SERVER_ERROR).build(); //Transaction was active
			}
		}
	}
	
}
