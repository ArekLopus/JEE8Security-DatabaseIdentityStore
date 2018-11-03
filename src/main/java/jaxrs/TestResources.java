package jaxrs;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.security.enterprise.SecurityContext;
import javax.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

//http://localhost:8080/JEE8Security-DatabaseIdentityStore/res/sec/secured
//http://localhost:8080/JEE8Security-DatabaseIdentityStore/res/sec/login
//http://localhost:8080/JEE8Security-DatabaseIdentityStore/res/sec/logout
@Path("sec")
@Produces(MediaType.TEXT_HTML)
public class TestResources {
	
	@Inject
	SecurityContext sc;
	
	@Context
	HttpServletRequest request;
	
	@Context
	HttpServletResponse response;
	
	@Path("login")
	@GET
	public String testLogin() {
		
		UsernamePasswordCredential credentials = new UsernamePasswordCredential("aa", "aa");
		sc.authenticate(request, response, AuthenticationParameters.withParams().credential(credentials));
		
		if(sc.getCallerPrincipal() == null) {
			return "Principal NULL";
		}
		String info = "Session: "+ request.getSession(false) 
				+ "<br/>User: " + sc.getCallerPrincipal().getName()
				+ "<br/>is caller in role 'admin' -> "+sc.isCallerInRole("admin")
				+ "<br/>is caller in role 'user' -> "+sc.isCallerInRole("user");
		
		return info;
	}
	
	@RolesAllowed("admin")
	@Path("secured")
	@GET
	public String testSecured() throws ServletException {
		
		if(sc.getCallerPrincipal() == null) {
			return "Principal NULL";
		}
		String info = "Session: "+ request.getSession(false) + ", id: " + (request.getSession(false) == null ? "" : request.getSession(false).getId())
				+ "<br/>User: " + sc.getCallerPrincipal().getName()
				+ "<br/>is caller in role 'admin' -> "+sc.isCallerInRole("admin")
				+ "<br/>is caller in role 'user' -> "+sc.isCallerInRole("user");
		
		return info;
	}
	
	@Path("logout")
	@GET
	public String testLogout() throws ServletException {
		String before = "Session before logout: "+ request.getSession(false);
		request.logout();
	    request.getSession().invalidate();
	    return before + "<br/>Logged out, session: " + request.getSession(false);
	}
	

	@POST
	public String testPost(@FormParam("name") String name, @FormParam("password") String password) throws ServletException {
		
		if (request.getSession(false) != null) {
			request.logout();
			request.getSession().invalidate();
		}
		
		UsernamePasswordCredential credentials = new UsernamePasswordCredential(name, password);
		
		sc.authenticate(request, response, AuthenticationParameters.withParams().credential(credentials));
		
		if(sc.getCallerPrincipal() == null) {
			return "Principal NULL";
		}
		String info = "POST Login"
				+ "<br/>User: " + sc.getCallerPrincipal().getName()
				+ "<br/>is caller in role 'admin' -> "+sc.isCallerInRole("admin")
				+ "<br/>is caller in role 'user' -> "+sc.isCallerInRole("user");
		
		return info;
	}

	
}
