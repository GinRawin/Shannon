package app;

import java.sql.Connection;
import java.sql.Statement;

public class UserDao {
  private Connection con;

  void filteredLiteral() throws Exception {
    Statement stmt = con.createStatement();
    stmt.executeQuery("SELECT * FROM users");
  }

  void retainedConcat(String id) throws Exception {
    Statement stmt = con.createStatement();
    stmt.executeQuery("SELECT * FROM users WHERE id=" + id);
  }

  void filteredLocalLiteral() throws Exception {
    String sql = "SELECT * FROM users";
    Statement stmt = con.createStatement();
    stmt.executeQuery(sql);
  }

  void retainedFormat(String id) throws Exception {
    String sql2 = String.format("SELECT * FROM users WHERE id=%s", id);
    Statement stmt = con.createStatement();
    stmt.executeQuery(sql2);
  }

  void unclassifiedSameName(Helper dao, String input) throws Exception {
    dao.executeQuery(input);
  }

  void unknownCustomMethod(Helper dao, String input) throws Exception {
    dao.executeSql(input);
  }
}
