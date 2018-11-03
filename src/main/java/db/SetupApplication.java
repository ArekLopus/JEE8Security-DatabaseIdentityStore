package db;

import javax.annotation.security.DeclareRoles;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Named;
import javax.security.enterprise.identitystore.DatabaseIdentityStoreDefinition;
import javax.security.enterprise.identitystore.Pbkdf2PasswordHash;

//@DatabaseIdentityStoreDefinition(
//	    dataSourceLookup = "${'java:global/CredentialsDS'}",
//	    callerQuery = "#{'select password from user where name = ?'}",
//	    groupsQuery = "select role from roles where name = ?",
//	    hashAlgorithm = Pbkdf2PasswordHash.class,
//	    priorityExpression = "#{100}",
//	    hashAlgorithmParameters = {
//	        "Pbkdf2PasswordHash.Iterations=3072",
//	        "${applicationConfig.dyna}"
//	    }
//	)
@DatabaseIdentityStoreDefinition(
	    dataSourceLookup = "java:global/CredentialsDS",
	    callerQuery = "select password from user where name = ?",
	    groupsQuery = "select role from roles where name = ?",
	    hashAlgorithm = Pbkdf2PasswordHash.class,
	    priorityExpression = "100",
	    hashAlgorithmParameters = {
	        "Pbkdf2PasswordHash.Iterations=4096",
	        "${setupApplication.dynamically}"
	    }
	)
@ApplicationScoped
@Named
@DeclareRoles({ "admin", "user", "foo" })
public class SetupApplication {

    public String[] getDynamically() {
        return new String[]{
        		"Pbkdf2PasswordHash.Algorithm=PBKDF2WithHmacSHA512",
        		"Pbkdf2PasswordHash.SaltSizeBytes=64",
        		"Pbkdf2PasswordHash.KeySizeBytes=64"
        	};
    }

}