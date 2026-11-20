package app;

import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Handler {
  void sources(HttpServletRequest request) {
    String id = request.getParameter("id");
    String name = request.getParameter("name");
    Object principal = request.getUserPrincipal();
    boolean admin = request.isUserInRole("ADMIN");
  }

  void command(HttpServletRequest request) throws Exception {
    String host = request.getParameter("host");
    Runtime.getRuntime().exec("ping " + host);
    Runtime.getRuntime().exec("ls");
    new ProcessBuilder("ping", host).start();
  }

  void xss(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String v = request.getParameter("v");
    PrintWriter out = response.getWriter();
    out.write("<h1>Hello</h1>");
    out.write(v);
  }

  void format(String userInput, String dynamicFormat) {
    String.format("123", userInput);
    String.format("%s", userInput);
    String.format(dynamicFormat, userInput);
  }

  void authz(HttpServletRequest request) {
    request.isUserInRole("ADMIN");
  }

  void authzNameOnly(Security security) {
    security.hasRole("ADMIN");
  }
}
