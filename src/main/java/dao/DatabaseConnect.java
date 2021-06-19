package dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConnect 
{
    //For Server	
	public static Connection connect() throws ClassNotFoundException, SQLException
    {
   	 Class.forName("org.sqlite.JDBC");
   	 Connection con=DriverManager.getConnection("jdbc:sqlite:C://sqlite-tools-win32-x86-3350500//msopenId.db");
   	 return con;
    }
	
	//For client
	public static Connection clientConnect() throws ClassNotFoundException, SQLException
    {
   	 Class.forName("org.sqlite.JDBC");
   	 Connection con=DriverManager.getConnection("jdbc:sqlite:C://sqlite-tools-win32-x86-3350500//msclient.db");
   	 return con;
    }
}

