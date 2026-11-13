package com.fixture.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class ReportDao {
    private final Connection connection;

    public ReportDao(Connection connection) {
        this.connection = connection;
    }

    public List<String> getReportById(String reportId) throws Exception {
        audit("reports.read");
        String query = "SELECT id, body FROM reports WHERE id = '" + reportId + "'";
        List<String> reports = new ArrayList<>();
        List<String> tracked = new ArrayList<>();
        Statement stmt = connection.createStatement();
        ResultSet rows = stmt.executeQuery(query);
        while (rows.next()) {
            reports.add(rows.getString("id"));
        }
        rows.close();
        stmt.close();
        return reports;
    }
}
