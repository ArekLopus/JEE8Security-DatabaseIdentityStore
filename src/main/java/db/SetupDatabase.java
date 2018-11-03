package db;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.annotation.Resource;
import javax.annotation.sql.DataSourceDefinition;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;
import javax.security.enterprise.identitystore.Pbkdf2PasswordHash;
import javax.sql.DataSource;

@DataSourceDefinition(
    name = "java:global/CredentialsDS",									// global to circumvent https://java.net/jira/browse/GLASSFISH-21447
    className = "org.h2.jdbcx.JdbcDataSource",
    //url="jdbc:h2:d:/ccc/h2db/data;DB_CLOSE_ON_EXIT=FALSE"
    url="jdbc:h2:mem:data;DB_CLOSE_ON_EXIT=FALSE"				// :mem:data is better, but TomEE insists on this being a file
)
@Singleton
@Startup
public class SetupDatabase {
    
    @Resource(lookup="java:global/CredentialsDS")
    private DataSource dataSource;

    @Inject
    private Pbkdf2PasswordHash passwordHash;
    
    @PostConstruct
    public void init() {
        
        Map<String, String> parameters= new HashMap<>();
        parameters.put("Pbkdf2PasswordHash.Iterations", "4096");
        parameters.put("Pbkdf2PasswordHash.Algorithm", "PBKDF2WithHmacSHA512");
        parameters.put("Pbkdf2PasswordHash.SaltSizeBytes", "64");
        parameters.put("Pbkdf2PasswordHash.KeySizeBytes", "64");
        passwordHash.initialize(parameters);
        
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP TABLE IF EXISTS user");
                statement.execute("DROP TABLE IF EXISTS roless");
                
                statement.execute("CREATE TABLE IF NOT EXISTS user(name VARCHAR(255) PRIMARY KEY, password VARCHAR(255))");
                statement.execute("CREATE TABLE IF NOT EXISTS roles(name VARCHAR(255), role VARCHAR(255))");
                
                statement.execute("INSERT INTO user VALUES('aa', '" + passwordHash.generate("aa".toCharArray()) + "')");
                statement.execute("INSERT INTO user VALUES('bb', '" + passwordHash.generate("bb".toCharArray()) + "')");
                
                statement.execute("INSERT INTO roles VALUES('aa', 'admin')");
                statement.execute("INSERT INTO roles VALUES('bb', 'admin')");
                statement.execute("INSERT INTO roles VALUES('bb', 'user')");
            }
            System.out.println("init() called");
            listUsers();
        } catch (SQLException e) {
           throw new IllegalStateException(e);
        }

    }
    
    @PreDestroy
    public void destroy() {
    	
    	try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                
                statement.execute("DROP TABLE IF EXISTS user");
                statement.execute("DROP TABLE IF EXISTS groups");
            }
        } catch (SQLException e) {
           throw new IllegalStateException(e);
        }
    	System.out.println("destroy() called");
    }
    
    protected void listUsers() {
    	
    	try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                try (ResultSet rs = statement.executeQuery("select * FROM user");) {
                	while (rs.next()) {
                        System.out.println("Name=" + rs.getString("name") + ",\tpass: " + rs.getString("password"));
                    }
                }
            }
        } catch (SQLException e) {
           throw new IllegalStateException(e);
        }
    }
}